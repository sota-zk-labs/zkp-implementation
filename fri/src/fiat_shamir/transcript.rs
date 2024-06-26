use ark_ff::PrimeField;
use rand::prelude::StdRng;
use rand::SeedableRng;
use sha2::Digest;
use std::marker::PhantomData;

/// A transcript for generating cryptographic challenges using the Fiat-Shamir transform with a cryptographic hash function and a prime field.
///
/// The `Transcript` struct maintains an internal state and accumulates data to produce cryptographic challenges using the Fiat-Shamir transform.
/// It utilizes a cryptographic hash function `T` and a prime field `F` for generating challenges.
///
/// # Type Parameters
///
/// - `T`: A type implementing the `Digest` trait from the `sha2` crate, used as the cryptographic hash function.
/// - `F`: A prime field type implementing the `PrimeField` trait from the `ark_ff` crate, used for generating challenges.
///
/// # Fiat-Shamir Transform
///
/// The Fiat-Shamir transform is a method for transforming a protocol that involves interactive proofs into one that is non-interactive,
/// using the output of a random oracle (hash function) to simulate the interaction.
///
/// # Examples
///
/// ```
/// use ark_ff::Field;
/// use rand::prelude::StdRng;
/// use rand::{Rng, SeedableRng};
/// use sha2::Sha256;
/// use fri::fiat_shamir::transcript::Transcript;
/// use fri::fields::goldilocks::Fq;
///
/// static SECRET_X: Fq = Fq::ZERO;
///
/// let mut transcript = Transcript::<Sha256, Fq>::new(SECRET_X);
/// let query = Fq::from(928459);
/// transcript.digest(query);
/// let c1 = transcript.generate_a_challenge();
/// ```
#[derive(Default, Clone)]
pub struct Transcript<T: Digest + Default, F: PrimeField> {
    data: Option<Vec<u8>>,
    index: u64,
    generated: bool,

    #[allow(dead_code)]
    /// Phantom data for annotation purposes.
    _phantom_data: PhantomData<T>,
    _phantom_data2: PhantomData<F>,
}

impl<T: Digest + Default, F: PrimeField> Transcript<T, F> {
    /// Constructs a new `Transcript` initialized with the given message value.
    ///
    /// # Parameters
    ///
    /// - `message`: A message value of type `F` used to initialize the transcript.
    ///
    /// # Returns
    ///
    /// A new `Transcript` initialized with the given message value.
    pub fn new(message: F) -> Self {
        let mut transcript = Self {
            data: None,
            index: 0,
            generated: true,
            _phantom_data: Default::default(),
            _phantom_data2: Default::default(),
        };
        transcript.digest(message);
        transcript
    }
}

impl<T: Digest + Default, F: PrimeField> Transcript<T, F> {
    /// Updates the transcript by digesting the provided message.
    ///
    /// # Parameters
    ///
    /// - `message`: A message of type `F` to be digested into the transcript.
    pub fn digest(&mut self, message: F) {
        let mut hasher = T::default();
        hasher.update(self.data.take().unwrap_or_default());
        hasher.update(self.index.to_le_bytes());
        hasher.update(message.to_string());
        self.data = Some(hasher.finalize().to_vec());
        self.index += 1;
        self.generated = false;
    }

    fn generate_rng_with_seed(&mut self) -> StdRng {
        if self.generated {
            panic!("I'm hungry! Feed me something first");
        }
        self.generated = true;
        let mut seed: [u8; 8] = Default::default();
        seed.copy_from_slice(&self.data.clone().unwrap_or_default()[0..8]);
        let seed = u64::from_le_bytes(seed);
        StdRng::seed_from_u64(seed)
    }

    /// Generates a cryptographic challenge using the internal state of the transcript.
    ///
    /// # Returns
    ///
    /// A cryptographic challenge of type `F`.
    pub fn generate_a_challenge(&mut self) -> F {
        let mut rng = self.generate_rng_with_seed();
        F::rand(&mut rng)
    }

    /// Generates multiple cryptographic challenges using the internal state of the transcript.
    ///
    /// # Parameters
    ///
    /// - `number`: The number of challenges to generate.
    ///
    /// # Returns
    ///
    /// A vector containing the generated cryptographic challenges.
    pub fn generate_challenges(&mut self, number: usize) -> Vec<F> {
        let mut rng = self.generate_rng_with_seed();
        (0..number).map(|_| F::rand(&mut rng)).collect()
    }

    /// Generates multiple cryptographic challenges as `usize` values using the internal state of the transcript.
    ///
    /// # Parameters
    ///
    /// - `number`: The number of challenges to generate.
    ///
    /// # Returns
    ///
    /// A vector containing the generated cryptographic challenges as `usize` values.
    pub fn generate_challenge_list_usize(&mut self, number: usize) -> Vec<usize> {
        self.generate_challenges(number)
            .into_iter()
            .map(|field| field.into_bigint().as_ref()[0] as usize)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Transcript;
    use crate::fields::goldilocks::Fq;
    use ark_ff::Field;
    use rand::prelude::StdRng;
    use rand::{Rng, SeedableRng};
    use sha2::Sha256;

    static SECRET_X: Fq = Fq::ZERO;

    #[test]
    fn test_generate_a_challenge_should_return_different() {
        // Ensure that each generated challenge is different when using different queries.
        let mut transcript = Transcript::<Sha256, Fq>::new(SECRET_X);
        let query = Fq::from(StdRng::from_entropy().gen::<u128>());
        transcript.digest(query);
        let c1 = transcript.generate_a_challenge();
        transcript.digest(query);
        let c2 = transcript.generate_a_challenge();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_generate_a_challenge_deterministic() {
        // Ensure that the same query generates the same challenge.
        let mut transcript = Transcript::<Sha256, Fq>::new(SECRET_X);
        let query = Fq::from(928459);

        let mut transcript2 = Transcript::<Sha256, Fq>::new(SECRET_X);
        transcript.digest(query);
        transcript2.digest(query);
        let c1 = transcript.generate_a_challenge();
        let c2 = transcript2.generate_a_challenge();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_generate_challenge_list_diff_elements() {
        // Ensure that a list of generated challenges contains different elements.
        let mut transcript = Transcript::<Sha256, Fq>::new(SECRET_X);
        let size = 5;
        transcript.digest(Fq::from(31313213));
        let g = transcript.generate_challenges(size);
        assert_eq!(g.len(), size);
        for i in 0..g.len() {
            for j in 0..i {
                assert_ne!(g[i].clone(), g[j].clone());
            }
        }
    }

    #[test]
    fn test_generate_challenge_list_deterministic() {
        // Ensure that generating challenges multiple times with the same inputs produces the same results.
        let mut transcript = Transcript::<Sha256, Fq>::new(SECRET_X);
        let mut transcript2 = Transcript::<Sha256, Fq>::new(SECRET_X);
        let size = 5;
        transcript.digest(Fq::from(31313213));
        transcript2.digest(Fq::from(31313213));
        let g = transcript.generate_challenges(size);
        let g2 = transcript2.generate_challenges(size);
        assert_eq!(g.len(), size);
        assert_eq!(g, g2);
    }

    #[test]
    #[should_panic]
    fn safe_guard() {
        // Ensure that panic is triggered when generating challenges without digesting any more queries.
        let mut transcript = Transcript::<Sha256, Fq>::new(SECRET_X);
        let size = 5;
        transcript.digest(Fq::from(StdRng::from_entropy().gen::<u128>()));
        let _g = transcript.generate_challenges(size);
        let _g2 = transcript.generate_challenges(size);
    }

    #[test]
    fn test_generate_index_list_diff_elements() {
        // Ensure that a list of generated challenges as `usize` values contains different elements.
        let mut transcript = Transcript::<Sha256, Fq>::new(SECRET_X);
        let size = 5;
        transcript.digest(Fq::from(31313213));
        let g = transcript.generate_challenge_list_usize(size);
        assert_eq!(g.len(), size);
        for i in 0..g.len() {
            for j in 0..i {
                assert_ne!(g[i].clone(), g[j].clone());
            }
        }
    }

    #[test]
    fn test_generate_index_list_deterministic() {
        // Ensure that generating challenges as `usize` values multiple times with the same inputs produces the same results.
        let mut transcript = Transcript::<Sha256, Fq>::new(SECRET_X);
        let mut transcript2 = Transcript::<Sha256, Fq>::new(SECRET_X);
        let size = 5;
        transcript.digest(Fq::from(31313213));
        transcript2.digest(Fq::from(31313213));
        let g = transcript.generate_challenge_list_usize(size);
        let g2 = transcript2.generate_challenge_list_usize(size);
        assert_eq!(g.len(), size);
        assert_eq!(g, g2);
    }
}

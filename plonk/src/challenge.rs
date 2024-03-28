use std::marker::PhantomData;

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalSerialize, Write};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::Digest;

use kzg::commitment::KzgCommitment;

/// Generates Fiat-Shamir challenges for the KZG scheme.
///
/// The `ChallengeGenerator` struct is responsible for generating challenges used in the KZG scheme.
#[derive(Clone, Default)]
pub struct ChallengeGenerator<T: Digest + Default> {
    data: Option<Vec<u8>>,
    generated: bool,

    #[allow(dead_code)]
    /// Phantom data for annotation purposes.
    _phantom_data: PhantomData<T>,
}

impl<T: Digest + Default> ChallengeGenerator<T> {
    /// Creates a new `ChallengeGenerator` instance from a list of commitments.
    ///
    /// # Parameters
    ///
    /// - `kzg_commitment`: A slice containing the commitments.
    ///
    /// # Returns
    ///
    /// A new `ChallengeGenerator` instance.
    pub fn from_commitment(kzg_commitment: &[KzgCommitment]) -> Self {
        let mut challenge_parse = Self::default();
        for commitment in kzg_commitment {
            challenge_parse.feed(commitment);
        }
        challenge_parse
    }
}

impl<T: Digest + Default> ChallengeGenerator<T> {
    /// Feeds a commitment to the challenge generator.
    ///
    /// # Parameters
    ///
    /// - `kzg_commitment`: The commitment to feed to the generator.
    pub fn feed(&mut self, kzg_commitment: &KzgCommitment) {
        let mut hasher = T::default();
        hasher.update(self.data.take().unwrap_or_default());
        kzg_commitment
            .inner()
            .serialize_uncompressed(HashMarshaller(&mut hasher))
            .expect("HashMarshaller::serialize_uncompressed should be infallible!");
        self.data = Some(hasher.finalize().to_vec());
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

    /// Generates challenges of a specified length.
    ///
    /// # Parameters
    ///
    /// - `N`: The length of the challenges to generate.
    ///
    /// # Returns
    ///
    /// An array of generated challenges.
    pub fn generate_challenges<const N: usize>(&mut self) -> [Fr; N] {
        let mut rng = self.generate_rng_with_seed();
        let points = [0; N];
        points.map(|_| Fr::rand(&mut rng))
    }
}

// This private struct works around Serialize taking the pre-existing
// std::io::Write instance of most digest::Digest implementations by value
struct HashMarshaller<'a, H: Digest>(&'a mut H);

impl<'a, H: Digest> Write for HashMarshaller<'a, H> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> ark_std::io::Result<usize> {
        Digest::update(self.0, buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> ark_std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use ark_ec::{AffineRepr, CurveGroup};
    use sha2::Sha256;

    use crate::types::G1Point;

    use super::*;

    #[test]
    fn aggregation_digest_test() {
        let commitment1 = KzgCommitment(G1Point::generator().mul(Fr::from(1)).into_affine());
        let commitment2 = KzgCommitment(G1Point::generator().mul(Fr::from(2)).into_affine());
        let commitments1: [KzgCommitment; 2] = [commitment1.clone(), commitment2.clone()];
        let [a, aa, aaa] =
            ChallengeGenerator::<Sha256>::from_commitment(&commitments1).generate_challenges();

        let commitments2: [KzgCommitment; 1] = [commitment2.clone()];
        let [b] =
            ChallengeGenerator::<Sha256>::from_commitment(&commitments2).generate_challenges();
        assert_ne!(a, b, "should be different");

        let commitments3: [KzgCommitment; 2] = [commitment1.clone(), commitment2.clone()];
        let [c, cc, ccc] =
            ChallengeGenerator::<Sha256>::from_commitment(&commitments3).generate_challenges();
        assert_eq!(a, c, "should be equal");
        assert_eq!(aa, cc, "should be equal");
        assert_eq!(aaa, ccc, "should be equal");
    }

    #[test]
    #[should_panic]
    fn safe_guard() {
        let commitment1 = KzgCommitment(G1Point::generator().mul(Fr::from(1)).into_affine());
        let commitments1: [KzgCommitment; 1] = [commitment1.clone()];
        let mut generator = ChallengeGenerator::<Sha256>::from_commitment(&commitments1);
        let [_a, _aa, _aaa] = generator.generate_challenges();
        let [_a, _aa, _aaa] = generator.generate_challenges();
    }
}

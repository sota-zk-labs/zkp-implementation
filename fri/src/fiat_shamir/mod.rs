use std::cmp::min;

use ark_ff::{BigInteger, PrimeField};
use rand::{Rng, rngs::StdRng, SeedableRng};

use crate::hasher::CustomizedHash;

/// A transcript generator in Fiat-Shamir transformation
/// A challenge will be hash of `(x,i,last_r,g_i)`
pub struct Transcript<F: PrimeField> {
    /// The last generated challenge
    last_r: F,

    /// The seed, which should be generated from the initialization step
    x: F,

    /// The current order of query points
    i: u64,

    /// The last query point
    gi: F,

    /// The number of remaining queries that have not been hashed
    remain_queries: u64,
}

impl<F: PrimeField> Transcript<F> {
    pub fn new() -> Self {
        Self {
            last_r: F::ZERO,
            x: F::from(StdRng::from_entropy().gen::<u128>()),
            i: 0,
            gi: F::ZERO,
            remain_queries: 0,
        }
    }

    fn check_append(&self) {
        if self.i == 0 {
            println!("Transcript has not been appended!")
        }
    }

    /// Prover use it to send a query
    ///
    /// # Arguments
    ///
    /// * `merkle_root`: the query
    pub fn append(&mut self, merkle_root: F) {
        self.i += 1;
        if self.remain_queries == 0 {
            self.gi = merkle_root;
        } else {
            self.gi = CustomizedHash::hash_two(self.gi, merkle_root);
        }
        self.remain_queries += 1;
    }

    /// Generate a single challenge
    ///
    /// returns: F: single challenge
    pub fn generate_a_challenge(&mut self) -> F {
        self.check_append();
        if self.remain_queries == 0 {
            return self.last_r;
        }
        let challenge = CustomizedHash::hash_two(
            CustomizedHash::hash_two(self.x, F::from(self.i as u128)),
            CustomizedHash::hash_two(self.last_r, self.gi),
        );
        self.last_r = challenge;
        self.remain_queries = 0;
        return challenge;
    }

    /// Generate a list of challenges with `number` elements
    ///
    /// # Arguments
    ///
    /// * `number`: the number of elements
    ///
    /// returns: Vec<F, Global>: list of challenges
    pub fn generate_challenge_list(&mut self, number: usize) -> Vec<F> {
        self.check_append();
        let mut challenges = Vec::<F>::new();
        for _ in 0..number {
            let c = self.generate_a_challenge();
            challenges.push(c);
            self.append(c);
        }
        challenges
    }


    /// Similar to generate_a_challenge
    pub fn generate_an_index(&mut self) -> usize {
        return Self::field_to_usize(&self.generate_a_challenge());
    }

    /// Similar to generate_challenge_list
    pub fn generate_index_list(&mut self, number: usize) -> Vec<usize> {
        return self.generate_challenge_list(number).
            iter().map(|&c| Self::field_to_usize(&c)).collect();
    }

    fn field_to_usize(el: &F) -> usize {
        let bytes = el.into_bigint().to_bytes_le();
        let mut res: u64 = 0;
        for i in (0..min(bytes.len(), 8)).rev() {
            res = (res << 8) | (bytes[i] as u64);
        }
        return res as usize;
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand::prelude::StdRng;

    use crate::fields::goldilocks::Fq;

    use super::Transcript;

    #[test]
    fn test_generate_a_challenge() {
        let mut transcript = Transcript::<Fq>::new();
        let query = Fq::from(StdRng::from_entropy().gen::<u128>());
        transcript.append(query);
        let c1 = transcript.generate_a_challenge();
        // transcript.append(query);
        let c2 = transcript.generate_a_challenge();
        println!("{:?} {:?}", c1.0, c2.0);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_generate_challenge_list() {
        let mut transcript = Transcript::<Fq>::new();
        let size = 5;
        transcript.append(Fq::from(StdRng::from_entropy().gen::<u128>()));
        let g = transcript.generate_challenge_list(size);
        println!("{:?}", g);
        assert_eq!(g.len(), size);
        for i in 0..g.len() {
            for j in 0..i {
                assert_ne!(g[i], g[j]);
            }
        }
    }

    #[test]
    fn test_generate_an_index() {
        let mut t = Transcript::<Fq>::new();
        t.append(Fq::from(182887487));
        let g1 = t.generate_an_index();
        let g2 = t.generate_an_index();
        println!("{} {}", g1, g2);
        assert_eq!(g1, g2);
    }

    #[test]
    fn test_generate_index_list() {
        let mut transcript = Transcript::<Fq>::new();
        let size = 5;
        transcript.append(Fq::from(StdRng::from_entropy().gen::<u128>()));
        let g = transcript.generate_index_list(size);
        println!("{:?}", g);
        assert_eq!(g.len(), size);
        for i in 0..g.len() {
            for j in 0..i {
                assert_ne!(g[i], g[j]);
            }
        }
    }
}

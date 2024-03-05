use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use rand::rngs::StdRng;
use rand::SeedableRng;
use kzg::KzgCommitment;
use sha2::{Digest, Sha256};
use sha2::digest::Update;

#[derive(Clone)]
struct ChallengeParse {
    data: Vec<u8>
}


impl ChallengeParse {
    pub fn new() -> Self {
        Self {
            data: vec![]
        }
    }

    fn inner(&self) -> &Vec<u8> {
        &self.data
    }


    pub fn digest(&mut self, kzg_commitment: &KzgCommitment) {
        kzg_commitment
            .inner()
            .serialize_unchecked(&mut self.data).unwrap();
    }

    pub fn with_digest(kzg_commitment: &[KzgCommitment]) -> Self {
        let mut generator = Self::new();
        for commitment in kzg_commitment {
            generator.digest(commitment);
        }

        generator
    }

    fn generate_rng_with_seed(self) -> StdRng {
        let mut hasher = Sha256::new();
        let data = self.inner().clone();
        hasher.update(data);
        let hash: Vec<u8> = hasher.finalize().to_vec();
        let mut seed: [u8; 8] = Default::default();
        seed.copy_from_slice(&hash[0..8]);
        let seed = u64::from_le_bytes(seed);
        StdRng::seed_from_u64(seed)
    }

    pub fn generate_challanges <const N: usize>(self) -> [Fr; N]{
        let mut rng = self.generate_rng_with_seed();
        let mut points = [];
        for i in 0..N {
            points.push(Fr::rand(&mut rng))
        }
        points
    }
}


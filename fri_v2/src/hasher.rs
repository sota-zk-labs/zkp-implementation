use ark_ff::{BigInteger, PrimeField};
use sha2::{Digest, Sha256};

pub trait Hasher<T: PrimeField>: Default {
    fn digest_vec(&mut self, data: &[T]);
    fn digest(&mut self, data: &T);
    fn finalize(&self) -> T;
}

pub struct Sha256Hasher {
    state: Sha256,
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Self {
            state: Sha256::new(),
        }
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: PrimeField> Hasher<T> for Sha256Hasher {
    fn digest_vec(&mut self, data: &[T]) {
        for element in data {
            self.digest(element);
        }
    }

    fn digest(&mut self, data: &T) {
        self.state.update(data.into_bigint().to_bytes_be());
    }

    fn finalize(&self) -> T {
        let a = self.state.clone().finalize();
        T::from_le_bytes_mod_order(a.as_slice())
        // let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fq>>::new(&[]);
        // let preimage = a.into_bigint().to_bytes_be(); // Converting to big-endian
        // let hashes: Vec<Fq> = hasher.hash_to_field(&preimage, 2); // Returned vector is of size 2
    }
}

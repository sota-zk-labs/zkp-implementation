use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct CustomizedHash<F: PrimeField> {
    _f: F,
}



impl<F: PrimeField> CustomizedHash <F> {

    pub fn new() -> CustomizedHash<F>{
        Self {
            _f: F::ZERO
        }
    }
    pub fn hash_one(data: F) -> F {
        let d: Vec<u8> = data.to_string().into();
        let mut hasher = Sha256::new();
        hasher.update(d);
        let h = hasher.finalize();
        F::from_le_bytes_mod_order(&h)
    }

    pub fn hash_two(data1: F, data2: F) -> F {
        let mut d: Vec<u8> = data1.to_string().into();
        let mut d1: Vec<u8> = data2.to_string().into();
        d.append(&mut d1);
        let mut hasher = Sha256::new();
        hasher.update(d);
        let h = hasher.finalize();
        F::from_le_bytes_mod_order(&h)
    }
}
use std::cmp::min;
use ark_ff::{BigInteger, PrimeField};

pub fn field_to_usize<F: PrimeField>(el: &F) -> usize {
    let bytes = el.into_bigint().to_bytes_le();
    let mut res: u64 = 0;
    for i in (0..min(bytes.len(), 8)).rev() {
        res = (res << 8) | (bytes[i] as u64);
    }
    return res as usize;
}
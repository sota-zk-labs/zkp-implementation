use ark_ff::PrimeField;

use crate::types::Poly;

pub trait PCS<F: PrimeField> {
    type Commitment;
    type Opening;

    fn new() -> Self;
    fn commit(&self, poly: &Poly<F>) -> Self::Commitment;
    fn open(&self, poly: &Poly<F>, z: F) -> Self::Opening;
}
use ark_ff::PrimeField;

use crate::commitment::PCS;
use crate::transcript::TranscriptProtocol;

pub trait Lookup<F: PrimeField, P: PCS<F>> {
    type Proof;
    type Element;
    fn new(table: Vec<Self::Element>) -> Self;
    fn prove(&self, transcript: &mut TranscriptProtocol<F>, pcs: &P) -> Self::Proof;

    fn add_witness(&mut self, witness: Self::Element) -> bool;
}


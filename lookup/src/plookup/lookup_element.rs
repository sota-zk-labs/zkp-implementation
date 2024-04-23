use std::marker::PhantomData;

use ark_ff::PrimeField;

use crate::commitment::PCS;
use crate::lookup::Lookup;
use crate::multiset::multiset::Multiset;
use crate::plookup::proof::PlookupProof;
use crate::transcript::TranscriptProtocol;

pub struct PLookupElement<F: PrimeField, P: PCS<F>> {
    f: Multiset<F>,
    t: Multiset<F>,
    phantom: PhantomData<P>
}

impl<F: PrimeField, P: PCS<F>> Lookup<F, P> for PLookupElement<F, P> {
    type Proof = PlookupProof;
    type Element = F;

    fn new(table: Vec<Self::Element>) -> Self {
        todo!()
    }

    fn prove(&self, transcript: &mut TranscriptProtocol<F>, pcs: &P) -> Self::Proof {
        todo!()
    }

    fn add_witness(&mut self, witness: Self::Element) -> bool {
        todo!()
    }
}

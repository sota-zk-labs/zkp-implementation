use std::collections::{BTreeSet, HashSet};
use std::marker::PhantomData;

use ark_ff::PrimeField;

use crate::commitment::PCS;
use crate::lookup::Lookup;
use crate::plookup::proof::PlookupProof;
use crate::transcript::TranscriptProtocol;

pub struct PLookupVector<F: PrimeField, P: PCS<F>> {
    f: HashSet<Vec<F>>,
    t: HashSet<Vec<F>>,
    phantom: PhantomData<P>
}

impl<F: PrimeField, P: PCS<F>> Lookup<F, P> for PLookupVector<F, P> {
    type Proof = PlookupProof;
    type Element = Vec<F>;

    fn new(table: Vec<Self::Element>) -> Self {
        let mut t = HashSet::new();
        for e in table {
            t.insert(e);
        }
        Self {
            f: HashSet::new(),
            t,
            phantom: PhantomData
        }
    }

    fn prove(&self, transcript: &mut TranscriptProtocol<F>, pcs: &P) -> Self::Proof {
        todo!()
    }

    fn add_witness(&mut self, witness: Self::Element) -> bool {
        if !self.t.contains(&witness) {
            return false;
        }
        if self.f.contains(&witness) {
            return false;
        }
        self.f.insert(witness);
        return true;
    }
}

#[cfg(test)]
mod test {
    use crate::lookup::Lookup;
    use crate::plookup::lookup_vector::PLookupVector;
    use crate::tests::tests::{F, KZG12_381};

    #[test]
    fn test_add_witness() {
        const BIT: i32 = 4;
        let mut v: Vec<Vec<F>> = vec![];
        for a in 0..(1<<BIT) {
            for b in 0..(1<<BIT) {
                v.push(vec![F::from(a), F::from(b), F::from(a ^ b)])
            }
        }
        let mut lookup = PLookupVector::<F, KZG12_381>::new(v);
        assert!(lookup.add_witness(vec![F::from(6), F::from(5), F::from(5^6)]));
        assert!(!lookup.add_witness(vec![F::from(6), F::from(5), F::from(5^6)]));
        assert!(lookup.add_witness(vec![F::from(3651), F::from(5), F::from(5^6)]);)
        // assert!(v.contains());
    }
}
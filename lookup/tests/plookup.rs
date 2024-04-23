use lookup::commitment::PCS;
use lookup::lookup::Lookup;
use lookup::plookup::lookup_vector::PLookupVector;
use lookup::tests::tests::{F, KZG12_381};
use lookup::transcript::{TranscriptLabel, TranscriptProtocol};

#[test]
fn test() {
    const BIT: i32 = 4;
    let mut v: Vec<Vec<F>> = vec![];
    for a in 0..(1<<BIT) {
        for b in 0..(1<<BIT) {
            v.push(vec![F::from(a), F::from(b), F::from(a ^ b)])
        }
    }
    let mut transcript = TranscriptProtocol::<F>::new(TranscriptLabel::NAME);
    let zeta = transcript.challenge_scalar(TranscriptLabel::ZETA);
    let mut lookup = PLookupVector::<F, KZG12_381>::new(v);

    // lookup.add_witness(vec![F::from(5), F::from(6), F::from(5 ^ 6)]);
}
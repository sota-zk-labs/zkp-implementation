use std::marker::PhantomData;

use ark_ff::{BigInteger, PrimeField};
use merlin::Transcript;

pub struct TranscriptProtocol<F: PrimeField>(Transcript, PhantomData<F>);

impl<F: PrimeField> TranscriptProtocol<F> {

    pub fn new(name: &'static [u8]) -> Self {
        Self(Transcript::new(name), PhantomData)
    }

    pub fn append_commitment(&mut self, label: &'static [u8], comm: &F) {
        // self.0.append_message(label, &comm.into().to_bytes_le());
    }

    pub fn append_scalar(&mut self, label: &'static [u8], s: &F) {
        self.0.append_message(label, &s.into_bigint().to_bytes_le())
    }

    pub fn challenge_scalar(&mut self, label: &'static [u8]) -> F {
        let mut buf = [0u8; 64];
        self.0.challenge_bytes(label, &mut buf);

        // let mut rng = test_rng();
        // Fr::rand(&mut rng)
        F::from_le_bytes_mod_order(&buf)
    }
}

pub struct TranscriptLabel;

impl TranscriptLabel {
    pub const NAME: &'static [u8]  = b"lookup";
    pub const ZETA: &'static [u8]  = b"zeta";
}


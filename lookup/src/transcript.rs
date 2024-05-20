use std::marker::PhantomData;

use ark_ff::{BigInteger, PrimeField};
use merlin::Transcript;

/// A transcript generator used in Fiat-Shamir transformation.
///
/// This struct is built on top of [Merlin](https://crates.io/crates/merlin)
pub struct TranscriptProtocol<F: PrimeField>(Transcript, PhantomData<F>);

impl<F: PrimeField> TranscriptProtocol<F> {
    /// Size of a challenge, depending on the field used.
    const MODULUS_BYTE_SIZE: usize = (F::MODULUS_BIT_SIZE / 8) as usize;
    pub fn new(name: &'static [u8]) -> Self {
        Self(Transcript::new(name), PhantomData)
    }

    pub fn append_commitment<Commitment: ToBytes>(
        &mut self,
        label: &'static [u8],
        comm: &Commitment,
    ) {
        self.0.append_message(label, &comm.to_bytes());
    }

    pub fn append_scalar(&mut self, label: &'static [u8], s: &F) {
        self.0.append_message(label, &s.into_bigint().to_bytes_le())
    }

    pub fn challenge_scalar(&mut self, label: &'static [u8]) -> F {
        let mut buf = vec![0u8; Self::MODULUS_BYTE_SIZE];
        self.0.challenge_bytes(label, &mut buf);
        F::from_le_bytes_mod_order(&buf)
    }
}

/// Elements appended in the transcript must implement this trait.
pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

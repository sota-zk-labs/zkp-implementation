mod ivc_prover;

use ark_ff::PrimeField;
use sha2::Digest;
use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;
use crate::circuit::{AugmentedCircuit, FCircuit};
use crate::nifs::{NIFSProof};
use crate::r1cs::{FInstance, FWitness};
use crate::transcript::Transcript;

/// zero knowledge proof for IVC
pub struct ZkIVCProof {
    pub u_i: FInstance,
    pub big_u_i: FInstance,
    pub com_t: Option<KzgCommitment>,
    pub folded_u_proof: Option<NIFSProof>,
}

pub struct IVCProof {
    pub u_i: FInstance,
    pub w_i: FWitness,
    pub big_u_i: FInstance,
    pub big_w_i: FWitness,
}

pub struct IVC <T: Digest + Default + ark_serialize::Write, F: PrimeField,  FC: FCircuit<F>> {
    scheme: KzgScheme,
    augmented_circuit: AugmentedCircuit<T, F, FC>,
    ivc_transcript: Transcript<T>,
}


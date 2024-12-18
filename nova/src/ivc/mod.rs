mod ivc_prover;
mod ivc_verifier;

use crate::circuit::{AugmentedCircuit, FCircuit};
use crate::nifs::NIFSProof;
use crate::r1cs::{FInstance, FWitness};
use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;
use sha2::Digest;

/// This struct is the zero knowledge proof for IVC
/// π = (U, u, com_T , π_U') where U' is the folded instance
/// of u and U.
pub struct ZkIVCProof {
    pub u_i: FInstance,
    pub big_u_i: FInstance,
    pub com_t: Option<KzgCommitment>,
    pub folded_u_proof: Option<NIFSProof>,
}

/// This struct is the proof for IVC: Π = (u, w) (U, W)
pub struct IVCProof {
    pub u_i: FInstance,
    pub w_i: FWitness,
    pub big_u_i: FInstance,
    pub big_w_i: FWitness,
}

#[allow(dead_code)]
impl IVCProof {
    pub fn new(u_i: &FInstance, w_i: &FWitness, big_u_i: &FInstance, big_w_i: &FWitness) -> Self {
        Self {
            u_i: u_i.clone(),
            w_i: w_i.clone(),
            big_u_i: big_u_i.clone(),
            big_w_i: big_w_i.clone(),
        }
    }

    // Generate a trivial IVC proof.
    pub fn trivial_ivc_proof(trivial_instance: &FInstance, trivial_witness: &FWitness) -> Self {
        Self {
            u_i: trivial_instance.clone(),
            w_i: trivial_witness.clone(),
            big_u_i: trivial_instance.clone(),
            big_w_i: trivial_witness.clone(),
        }
    }
}

#[allow(dead_code)]
impl ZkIVCProof {
    pub fn trivial_zk_ivc_proof(trivial_instance: &FInstance) -> Self {
        Self {
            u_i: trivial_instance.clone(),
            big_u_i: trivial_instance.clone(),
            com_t: None,
            folded_u_proof: None,
        }
    }
}

/// IVC structure includes a scheme for commitment and an augmented F' function
pub struct IVC<T: Digest + Default + ark_serialize::Write, FC: FCircuit> {
    pub scheme: KzgScheme,
    pub augmented_circuit: AugmentedCircuit<T, FC>,
}

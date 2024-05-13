use ark_ff::{PrimeField, Zero};
use sha2::Digest;
use kzg::types::{BaseField, ScalarField};
use crate::circuit::{FCircuit};
use crate::ivc::{IVC, IVCProof, ZkIVCProof};
use crate::nifs::NIFS;
use crate::r1cs::R1CS;
use crate::transcript::Transcript;

impl <T: Digest + Default + ark_serialize::Write, F: PrimeField, FC: FCircuit<F> > IVC <T, F, FC> {
    pub fn prove(
        &self,
        prover_transcript: &mut Transcript<T>,
        r1cs: &R1CS<ScalarField>,
        i: BaseField,
        ivc_proof: &IVCProof,
    ) -> ZkIVCProof {

        if ! i.is_zero() {
            let (big_w_out, big_u_out, com_t, r) = NIFS::<T>::prover(
                &r1cs,
                &ivc_proof.w_i,
                &ivc_proof.big_w_i,
                &ivc_proof.u_i,
                &ivc_proof.big_u_i,
                &self.scheme,
                prover_transcript,
            );

            let nifs_proof = NIFS::<T>::prove(r, &big_w_out, &big_u_out, &self.scheme, prover_transcript);

            ZkIVCProof {
                u_i: ivc_proof.u_i.clone(),
                big_u_i: ivc_proof.big_u_i.clone(),
                com_t: Some(com_t),
                folded_u_proof: Some(nifs_proof)
            }
        } else {
            ZkIVCProof {
                u_i: ivc_proof.u_i.clone(),
                big_u_i: ivc_proof.big_u_i.clone(),
                com_t: None,
                folded_u_proof: None
            }
        }
    }
}
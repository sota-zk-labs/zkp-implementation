use crate::circuit::FCircuit;
use crate::ivc::{IVCProof, ZkIVCProof, IVC};
use crate::nifs::NIFS;
use crate::r1cs::{FInstance, FWitness, R1CS};
use crate::transcript::Transcript;
use ark_ff::Zero;
use kzg::types::ScalarField;
use sha2::Digest;

#[allow(dead_code)]
impl<T: Digest + Default + ark_serialize::Write, FC: FCircuit> IVC<T, FC> {
    /// IVC prover will fold 2 instance-witness pairs into one via NIFS
    /// and generate zkSNARK proof for it.
    pub fn prove(
        &self,
        r1cs: &R1CS<ScalarField>,
        ivc_proof: &IVCProof,
        prover_transcript: &mut Transcript<T>,
    ) -> (FWitness, FInstance, ZkIVCProof) {
        let i = self.augmented_circuit.i;
        if !i.is_zero() {
            // 1 + 2. Parse Π and compute U', W' and com_T
            let (big_w_out, big_u_out, com_t, r) = NIFS::<T>::prover(
                r1cs,
                &ivc_proof.w_i,
                &ivc_proof.big_w_i,
                &ivc_proof.u_i,
                &ivc_proof.big_u_i,
                &self.scheme,
                prover_transcript,
            );

            // 3. Generate zkSNARK proof
            let nifs_proof =
                NIFS::<T>::prove(r, &big_w_out, &big_u_out, &self.scheme, prover_transcript);

            (
                big_w_out,
                big_u_out,
                ZkIVCProof {
                    u_i: ivc_proof.u_i.clone(),
                    big_u_i: ivc_proof.big_u_i.clone(),
                    com_t: Some(com_t),
                    folded_u_proof: Some(nifs_proof),
                },
            )
        } else {
            (
                ivc_proof.big_w_i.clone(),
                ivc_proof.big_u_i.clone(),
                ZkIVCProof {
                    u_i: ivc_proof.u_i.clone(),
                    big_u_i: ivc_proof.big_u_i.clone(),
                    com_t: None,
                    folded_u_proof: None,
                },
            )
        }
    }
}

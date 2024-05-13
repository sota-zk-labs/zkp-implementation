use ark_ff::{BigInteger, One, PrimeField, Zero};
use sha2::Digest;
use kzg::types::{BaseField, ScalarField};
use crate::circuit::{AugmentedCircuit, FCircuit, State};
use crate::ivc::{IVC, ZkIVCProof};
use crate::nifs::NIFS;

impl <T: Digest + Default + ark_serialize::Write, F: PrimeField, FC: FCircuit<F> > IVC <T, F, FC> {
    pub fn verify(
        &mut self,
        i: BaseField,
        z_0: &State,
        z_i: &State,
        zk_ivc_proof: ZkIVCProof
    ) -> Result<(), String> {
        if i == BaseField::zero() {
            return if z_0.state == z_i.state {
                Ok(())
            } else {
                Err(String::from("Verify failed: wrong state"))
            }
        } else {

            // 1. parse zkIVCProof = (U, u, comT, nifs_proof)
            let u_i = zk_ivc_proof.u_i;
            let big_u_i = zk_ivc_proof.big_u_i;
            if zk_ivc_proof.com_t.is_none() {
                return Err(String::from("Verify failed: commitment of cross term T is wrong"));
            }

            if zk_ivc_proof.folded_u_proof.is_none() {
                return Err(String::from("Verify failed: commitment of cross term T is wrong"));
            }
            let com_t = zk_ivc_proof.com_t.unwrap();
            let folded_u_proof = zk_ivc_proof.folded_u_proof.unwrap();

            // 2. check that u.x = hash(i, z_0, z_i, U)
            let hash_io = AugmentedCircuit::<T, F, FC>::hash_io(i, z_0, z_i, &big_u_i);
            let hash_fr = ScalarField::from_le_bytes_mod_order(&hash_io.into_bigint().to_bytes_le());
            if u_i.x[0] != hash_fr {
                return Err(String::from("Verify failed: Public IO is wrong"));
            }

            // 3. check that u_i.comE = com_([0,...]) and u_i.u = 1
            if u_i.com_e != self.augmented_circuit.trivial_instance.com_e {
                return Err(String::from("Verify failed: Commitment of E is wrong"));
            }
            if u_i.u.is_one() {
                return Err(String::from("Verify failed: Scalar u is wrong"));
            }

            // 4. compute U' = NIFS.V(U, u, comT)
            let big_u_out = NIFS::<T>::verifier(folded_u_proof.r, &u_i, &big_u_i, &com_t);

            // 5. verify that zkSNARK.V(U', pi_U') = 1
            let res = NIFS::<T>::verify(&folded_u_proof, &u_i, &big_u_i, &big_u_out, &com_t, &self.scheme, &mut self.ivc_transcript);

            res

        }
    }
}
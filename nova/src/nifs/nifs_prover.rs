use sha2::Digest;
use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;
use kzg::types::ScalarField;
use crate::nifs::{FInstance, FWitness, NIFS, NIFSProof};
use crate::r1cs::R1CS;
use crate::transcript::Transcript;


impl <T: Digest + Default> NIFS<T> {

    pub fn prover(
        r1cs: &R1CS<ScalarField>,
        fw1: &FWitness,
        fw2: &FWitness,
        fi1: &FInstance,
        fi2: &FInstance,
        scheme: &KzgScheme,
        transcript: &mut Transcript<T>
    ) -> (FWitness, FInstance, KzgCommitment, ScalarField) {
        let mut z1 = fw1.w.clone();
        z1.append(&mut fi1.x.clone());
        z1.push(fi1.u);

        let mut z2 = fw2.w.clone();
        z2.append(&mut fi2.x.clone());
        z2.push(fi2.u);

        let t = NIFS::<T>::compute_t(&r1cs, fi1.u, fi2.u, &z1, &z2);
        let com_t = scheme.commit_vector(&t);

        transcript.feed_scalar_num(fi1.u);
        transcript.feed_scalar_num(fi2.u);
        transcript.feed(&com_t);
        let [r] = transcript.generate_challenges();

        let new_witness = NIFS::<T>::fold_witness(r, fw1, fw2, &t);
        let new_instance = NIFS::<T>::fold_instance(r, fi1, fi2, &com_t);

        (new_witness, new_instance, com_t, r)
    }

    pub fn prove(
        r: ScalarField,
        fw: &FWitness,
        fi: &FInstance,
        scheme: &KzgScheme,
        transcript: &mut Transcript<T>,
    ) -> NIFSProof {

        // opening = Transcript(fi_cmE, fi_cmW);
        transcript.feed(&fi.com_e);
        transcript.feed(&fi.com_w);
        let [opening_point] = transcript.generate_challenges();

        let opening_e = scheme.open_vector(&fw.e, opening_point);
        let opening_w = scheme.open_vector(&fw.w, opening_point);

        NIFSProof {
            r,
            opening_point,
            opening_e: opening_e,
            opening_w: opening_w
        }
    }
}

use crate::nifs::{FInstance, FWitness, NIFSProof, NIFS};
use crate::r1cs::R1CS;
use crate::transcript::Transcript;
use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;
use kzg::types::ScalarField;
use sha2::Digest;

impl<T: Digest + Default> NIFS<T> {
    /// Prover output a folded instance-witness pair, com_T and challenge r via Fiat-Shamir
    pub fn prover(
        r1cs: &R1CS<ScalarField>,
        fw1: &FWitness,
        fw2: &FWitness,
        fi1: &FInstance,
        fi2: &FInstance,
        scheme: &KzgScheme,
        transcript: &mut Transcript<T>,
    ) -> (FWitness, FInstance, KzgCommitment, ScalarField) {
        // generate Z = (W, x, u)
        let mut z1 = fw1.w.clone();
        z1.append(&mut fi1.x.clone());
        z1.push(fi1.u);

        let mut z2 = fw2.w.clone();
        z2.append(&mut fi2.x.clone());
        z2.push(fi2.u);

        let t = NIFS::<T>::compute_t(r1cs, fi1.u, fi2.u, &z1, &z2);
        let com_t = scheme.commit_vector(&t);

        transcript.feed_scalar_num(fi1.u);
        transcript.feed_scalar_num(fi2.u);
        transcript.feed(&com_t);
        let [r] = transcript.generate_challenges();

        let new_witness = NIFS::<T>::fold_witness(r, fw1, fw2, &t);
        let new_instance = NIFS::<T>::fold_instance(r, fi1, fi2, &com_t);

        (new_witness, new_instance, com_t, r)
    }

    /// Generate NIFS proof. Create openings by using KZG commitment
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
            opening_e,
            opening_w,
        }
    }
}

#[cfg(test)]

mod test {
    use super::*;
    use crate::nifs::nifs_verifier::gen_test_values;
    use crate::r1cs::is_r1cs_satisfied;
    use kzg::srs::Srs;
    use sha2::Sha256;

    #[test]
    pub fn test_prover_folding() {
        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3, 4]);
        let (matrix_a, _, _) = (
            r1cs.matrix_a.clone(),
            r1cs.matrix_b.clone(),
            r1cs.matrix_c.clone(),
        );

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);

        // Generate witnesses and instances
        let w: Vec<FWitness> = witnesses
            .iter()
            .map(|witness| FWitness::new(witness, matrix_a.len()))
            .collect();
        let u: Vec<FInstance> = w
            .iter()
            .zip(x)
            .map(|(w, x)| w.commit(&scheme, &x))
            .collect();

        let mut transcript = Transcript::<Sha256>::default();

        let (folded_witness, folded_instance, _, _) =
            NIFS::<Sha256>::prover(&r1cs, &w[0], &w[1], &u[0], &u[1], &scheme, &mut transcript);

        let ok = is_r1cs_satisfied(&r1cs, &folded_instance, &folded_witness, &scheme);

        if ok.is_err() {
            println!("{:?}", ok);
        }
        assert!(ok.is_ok());
    }
}

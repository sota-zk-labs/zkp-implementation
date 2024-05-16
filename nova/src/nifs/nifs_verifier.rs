use ark_ff::PrimeField;
use sha2::Digest;
use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;
use kzg::types::ScalarField;
use crate::nifs::{FInstance, NIFS, R1CS, NIFSProof};
use crate::transcript::Transcript;
use crate::utils::{to_f_matrix, to_f_vec};


impl <T: Digest + Default> NIFS<T> {

    /// NIFS.V generate the folded instance.
    pub fn verifier(
        r: ScalarField,
        fi1: &FInstance,
        fi2: &FInstance,
        com_t: &KzgCommitment,
    ) -> FInstance {
        NIFS::<T>::fold_instance(r, fi1, fi2, com_t)
    }

    /// NIFS.V can verify whether the Prover folding process was done
    /// correctly or not via the NIFS proof.
    pub fn verify(
        proof: &NIFSProof,
        fi1: &FInstance,
        fi2: &FInstance,
        fi3: &FInstance, // folded instance.
        com_t: &KzgCommitment,
        scheme: &KzgScheme,
        transcript: &mut Transcript<T>
    ) -> Result<(), String> {

        // verify challenge.
        let mut res = Self::verify_challenge(proof.r, fi1.u, fi2.u, com_t, transcript);
        if res.is_err() {
            return res;
        }

        // verify opening.
        res = Self::verify_opening(proof, fi3, scheme, transcript);
        if res.is_err() {
            return res;
        }

        Ok(())
    }

    /// Verify challenge r via Fiat-Shamir
    pub fn verify_challenge(
        r: ScalarField,
        fi1_u: ScalarField,
        fi2_u: ScalarField,
        com_t: &KzgCommitment,
        transcript: &mut Transcript<T>
    ) -> Result<(), String> {
        // Recreate challenge r
        transcript.feed_scalar_num(fi1_u);
        transcript.feed_scalar_num(fi2_u);
        transcript.feed(&com_t);

        let [new_r] = transcript.generate_challenges();

        // Verify that proof.r = Transcript(fi1.u, fi2.u, cmT)
        if new_r != r {
            return Err(String::from("Verify: Error in computing random r"))
        }

        Ok(())
    }

    /// Verify KZG opening
    pub fn verify_opening(
        proof: &NIFSProof,
        fi3: &FInstance, // folded instance.
        scheme: &KzgScheme,
        transcript: &mut Transcript<T>
    ) -> Result<(), String> {
        transcript.feed(&fi3.com_e);
        transcript.feed(&fi3.com_w);
        // Verify Opening_point = Transcript(fi1.cmE, fi1.cmW)
        let [opening_point] = transcript.generate_challenges();
        if opening_point != proof.opening_point {
            return Err(String::from("Verify: Error in computing random opening point"));
        }

        // Verify opening
        if !scheme.verify(&fi3.com_w, &proof.opening_w, opening_point) {
            return Err(String::from("Verify: Folding wrong at W"));
        }

        if !scheme.verify(&fi3.com_e, &proof.opening_e, opening_point) {
            return Err(String::from("Verify: Folding wrong at E"));
        }

        Ok(())
    }
}

#[allow(dead_code)]
/// This function is only used for generate test values such as: r1cs matrices, W, x.
pub fn gen_test_values<F: PrimeField>(inputs: Vec<usize>) -> (R1CS<F>, Vec<Vec<F>>, Vec<Vec<F>>) {
    // R1CS for: x^3 + x + 5 = y (example from article
    // https://vitalik.eth.limo/general/2016/12/10/qap.html )

    let a = to_f_matrix::<F>(vec![
        vec![1, 0, 0, 0, 0, 0],
        vec![0, 1, 0, 0, 0, 0],
        vec![1, 0, 1, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 5],
    ]);
    let b = to_f_matrix::<F>(vec![
        vec![1, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0],
        vec![0, 0, 0, 0, 0, 1],
        vec![0, 0, 0, 0, 0, 1],
    ]);
    let c = to_f_matrix::<F>(vec![
        vec![0, 1, 0, 0, 0, 0],
        vec![0, 0, 1, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 0],
        vec![0, 0, 0, 0, 1, 0],
    ]);

    // generate n witnesses
    let mut w: Vec<Vec<F>> = Vec::new();
    let mut x: Vec<Vec<F>> = Vec::new();
    for input in inputs {
        let w_i = to_f_vec::<F>(vec![
            input,
            input * input,                     // x^2
            input * input * input,             // x^2 * x
            input * input * input + input,     // x^3 + x
        ]);
        w.push(w_i.clone());
        let x_i = to_f_vec::<F>(vec![input * input * input + input + 5]);  // output: x^3 + x + 5
        x.push(x_i.clone());
    }

    let r1cs = R1CS::<F> { matrix_a: a, matrix_b: b, matrix_c: c, num_io: 1, num_vars: 4 };
    (r1cs, w, x)
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use sha2::Sha256;
    use kzg::srs::Srs;
    use crate::nifs::{FWitness, NIFS};

    #[test]
    fn test_one_fold() {
        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values(vec![3, 4]);
        let (matrix_a, _, _) = (r1cs.matrix_a.clone(), r1cs.matrix_b.clone(), r1cs.matrix_c.clone());

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);

        let mut prover_transcript = Transcript::<Sha256>::default();
        let mut verifier_transcript = Transcript::<Sha256>::default();

        // generate witnesses and instances
        let fw1 = FWitness::new(&witnesses[0], matrix_a.len());
        let fw2 = FWitness::new(&witnesses[1], matrix_a.len());

        let fi1 = fw1.commit(&scheme, &x[0]);
        let fi2 = fw2.commit(&scheme, &x[1]);

        let (p_folded_witness, p_folded_instance, com_t, r) = NIFS::prover(&r1cs, &fw1, &fw2, &fi1, &fi2, &scheme, &mut prover_transcript);

        let proof = NIFS::<Sha256>::prove(r, &p_folded_witness, &p_folded_instance, &scheme, &mut prover_transcript);
        let v_folded_instance = NIFS::<Sha256>::verifier(r, &fi1, &fi2, &com_t);

        let result = NIFS::<Sha256>::verify(&proof, &fi1, &fi2, &v_folded_instance, &com_t, &scheme, &mut verifier_transcript);
        println!("{:?}", result);
        assert!(result.is_ok());
    }
}
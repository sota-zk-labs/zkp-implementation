use ark_ff::PrimeField;
use sha2::Digest;
use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;
use crate::nifs::{FInstance, NIFS, R1CS, NIFSProof};
use crate::transcript::Transcript;
use crate::utils::{to_f_matrix, to_f_vec};


impl <T: Digest + Default> NIFS<T> {
    pub fn verify(
        proof: NIFSProof,
        fi1: &FInstance,
        fi2: &FInstance,
        fi3: &FInstance, // folded instance.
        com_t: &KzgCommitment,
        scheme: &KzgScheme,
        transcript: &mut Transcript<T>
    ) -> Result<(), String> {

        transcript.feed_scalar_num(fi1.u);
        transcript.feed_scalar_num(fi2.u);
        transcript.feed(&com_t);
        // Verify that proof.r = Transcript(fi1.u, fi2.u, cmT)
        let [r] = transcript.generate_challenges();
        // println!("verifier_r: {:?}", r);
        // println!("prover_r: {:?}", proof.r);
        // println!("{:?}", r == proof.r);
        if r != proof.r {
            return Err(String::from("Verify: Error in computing random r"))
        }

        transcript.feed(&fi3.com_e);
        transcript.feed(&fi3.com_w);
        // Verify Opening_point = Transcript(fi1.cmE, fi1.cmW)
        let [opening_point] = transcript.generate_challenges();
        if opening_point != proof.opening_point {
            return Err(String::from("Verify: Error in computing random opening point"))
        }
        // println!("fi.cW is2: {:?}", fi3.cW);
        // println!("openingW is2: {:?}", proof.openingW);
        // println!("opening_point is2: {:?}", opening_point);

        if !scheme.verify(&fi3.com_w, &proof.opening_w, opening_point) {
            return Err(String::from("Verify: Folding wrong at W"));
        }

        if !scheme.verify(&fi3.com_e, &proof.opening_e, opening_point) {
            return Err(String::from("Verify: Folding wrong at E"));
        }

        Ok(())
    }
}

pub fn gen_test_values<F: PrimeField>(n: usize) -> (R1CS<F>, Vec<Vec<F>>, Vec<Vec<F>>) {
    // R1CS for: x^3 + x + 5 = y (example from article
    // https://vitalik.eth.limo/general/2016/12/10/qap.html )

    let a = to_f_matrix::<F>(vec![
        vec![0, 1, 0, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 0],
        vec![0, 1, 0, 0, 1, 0],
        vec![5, 0, 0, 0, 0, 1],
    ]);
    let b = to_f_matrix::<F>(vec![
        vec![0, 1, 0, 0, 0, 0],
        vec![0, 1, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0],
    ]);
    let c = to_f_matrix::<F>(vec![
        vec![0, 0, 0, 1, 0, 0],
        vec![0, 0, 0, 0, 1, 0],
        vec![0, 0, 0, 0, 0, 1],
        vec![0, 0, 1, 0, 0, 0],
    ]);

    // generate n witnesses
    let mut w: Vec<Vec<F>> = Vec::new();
    let mut x: Vec<Vec<F>> = Vec::new();
    for i in 0..n {
        let input = 3 + i;
        let w_i = to_f_vec::<F>(vec![
            1,
            input,
            input * input * input + input + 5, // x^3 + x + 5
            input * input,                     // x^2
            input * input * input,             // x^2 * x
            input * input * input + input,     // x^3 + x
        ]);
        w.push(w_i.clone());
        let x_i = to_f_vec::<F>(vec![input * input * input + input + 5]);
        x.push(x_i.clone());
    }
    // println!("w: {:?}", w);
    // println!("x: {:?}", x);

    let r1cs = R1CS::<F> { matrix_a: a, matrix_b: b, matrix_c: c, num_io: 1, num_vars: 6 };
    (r1cs, w, x)
}

#[cfg(test)]

mod tests {
    use super::*;
    use sha2::Sha256;
    use kzg::srs::Srs;
    use crate::nifs::{FWitness, NIFS};

    #[test]
    fn test_one_fold() {
        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values(2);
        let (matrix_a, _, _) = (r1cs.matrix_a.clone(), r1cs.matrix_b.clone(), r1cs.matrix_c.clone());

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);

        let mut prover_transcript = Transcript::<Sha256>::default();
        let mut verifier_transcript = Transcript::<Sha256>::default();

        let fw1 = FWitness::new(&witnesses[0], matrix_a.len());
        let fw2 = FWitness::new(&witnesses[1], matrix_a.len());

        let fi1 = fw1.commit(&scheme, &x[0]);
        let fi2 = fw2.commit(&scheme, &x[1]);

        let (p_folded_witness, p_folded_instance, com_t, r) = NIFS::prover(&r1cs, &fw1, &fw2, &fi1, &fi2, &scheme, &mut prover_transcript);

        let proof = NIFS::<Sha256>::prove(r, &p_folded_witness, &p_folded_instance, &scheme, &mut prover_transcript);
        let v_folded_instance = NIFS::<Sha256>::verifier(r, &fi1, &fi2, &com_t);

        let result = NIFS::<Sha256>::verify(proof, &fi1, &fi2, &v_folded_instance, &com_t, &scheme, &mut verifier_transcript);
        println!("{:?}", result);
        assert!(result.is_ok());
    }
}
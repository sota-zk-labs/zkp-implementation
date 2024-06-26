use crate::fiat_shamir::transcript::Transcript;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use sha2::Digest;

use crate::merkle_tree::verify_merkle_proof;
use crate::prover::{Decommitment, Proof};

/// Verify proof of FRI prover of 2 phase
///
/// Folding phase and query phase
///
/// This is the only method you should call for verifying
pub fn verify<T: Digest + Default, F: PrimeField>(proof: Proof<F>) -> Result<(), String> {
    // regenerate random_r list
    let merkle_roots = proof.layers_root;
    let mut transcript = Transcript::<T, F>::new(F::ZERO);
    let random_r_list = merkle_roots
        .into_iter()
        .map(|root| {
            transcript.digest(root);
            transcript.generate_a_challenge()
        })
        .collect::<Vec<_>>();
    transcript.digest(proof.const_val);

    // regenerate challenge list
    let new_challenge_list = transcript
        .generate_challenge_list_usize(proof.number_of_queries)
        .into_iter()
        .map(|v| v % proof.domain_size)
        .collect::<Vec<_>>();

    // verify each query
    for (challenge, decommitment) in new_challenge_list
        .into_iter()
        .zip(proof.decommitment_list.into_iter())
    {
        verify_query(
            &challenge,
            &decommitment,
            &random_r_list,
            proof.domain_size,
            proof.const_val,
            proof.coset,
        )?
    }
    Ok(())
}

fn verify_query<F: PrimeField>(
    challenge: &usize,
    decommitment: &Decommitment<F>,
    random_r_list: &[F],
    domain_size: usize,
    const_val: F,
    coset: F,
) -> Result<(), String> {
    let mut cur_domain_size = domain_size;
    let mut cur_coset = coset;
    let two = F::from(2u128);

    for (((((i, eval), path), sym_eval), sym_path), random_r) in decommitment
        .evaluations
        .iter()
        .enumerate()
        .zip(decommitment.auth_paths.iter())
        .zip(decommitment.sym_evaluations.iter())
        .zip(decommitment.sym_auth_paths.iter())
        .zip(random_r_list.iter())
    {
        let index = challenge % cur_domain_size;
        let sym_index = (index + cur_domain_size / 2) % cur_domain_size;
        let cur_domain = <GeneralEvaluationDomain<F>>::new(cur_domain_size).unwrap();

        // verify path of merkle root
        if index != path.index || sym_index != sym_path.index {
            return Err(String::from("wrong index!"));
        }

        if *eval != path.leaf_val || *sym_eval != sym_path.leaf_val {
            return Err(String::from(
                "the evaluation does not correspond to given path!",
            ));
        }

        if !verify_merkle_proof(path) || !verify_merkle_proof(sym_path) {
            return Err(String::from("verify Merkle path failed!"));
        }

        // verify folding
        // Another way to compute q_fold let q_fold = (*eval + sym_eval) / two + (*random_r * (*eval - sym_eval)/(two * w_i));
        let w_i = cur_domain.element(index) * cur_coset;

        let q_fold =
            (*random_r + w_i) * eval / (two * w_i) - (*random_r - w_i) * sym_eval / (two * w_i);

        if i != decommitment.evaluations.len() - 1 {
            let next_layer_evaluation = decommitment.evaluations[i + 1];
            if q_fold != next_layer_evaluation {
                return Err(String::from("folding wrong!"));
            }
            cur_domain_size /= 2;
            cur_coset = cur_coset.square();
            continue;
        }

        if q_fold != const_val {
            // end of the folding process, the result must be equal to constant value
            return Err(String::from("folding wrong!"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::DenseUVPolynomial;
    use sha2::Sha256;

    use crate::fields::goldilocks::Fq;
    use crate::prover::generate_proof;

    use super::*;

    #[test]
    fn test_verifier() {
        let coeff = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coeff);

        let blowup_factor: usize = 2;
        let number_of_queries: usize = 2;
        let proof = generate_proof::<Sha256, Fq>(poly, blowup_factor, number_of_queries);
        let result = verify::<Sha256, Fq>(proof);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verifier2() {
        let coeff = vec![
            Fq::from(1),
            Fq::from(2),
            Fq::from(3),
            Fq::from(4),
            Fq::from(5),
            Fq::from(6),
        ];
        let poly = DensePolynomial::from_coefficients_vec(coeff);

        let blowup_factor: usize = 2;
        let number_of_queries: usize = 2;
        let proof = generate_proof::<Sha256, Fq>(poly, blowup_factor, number_of_queries);
        let result = verify::<Sha256, Fq>(proof);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verifier3() {
        let coeff = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coeff);

        let blowup_factor: usize = 2;
        let number_of_queries: usize = 2;
        let mut proof = generate_proof::<Sha256, Fq>(poly, blowup_factor, number_of_queries);

        proof.const_val -= Fq::from(1);
        let result = verify::<Sha256, Fq>(proof);
        assert!(result.is_err());
    }
}

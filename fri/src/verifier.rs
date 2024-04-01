use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use crate::fiat_shamir::Transcript;
use crate::merkle_tree::verify_merkle_proof;
use crate::prover::{Decommitment, Proof};

pub fn verify<F: PrimeField>(proof: Proof<F>) -> Result<(), String>{

    // regenerate random_r list
    let merkle_roots = proof.layers_root.clone();
    let mut transcript = Transcript::<F>::new();
    let random_r_list = merkle_roots.iter().map(|root| {
        transcript.append(root.clone());
        transcript.generate_a_challenge()
    }).collect::<Vec<F>>();
    transcript.append(proof.const_val.clone());

    // regenerate challenge list
    let new_challenge_list = transcript.generate_index_list(proof.number_of_queries).iter().map(|v| {
        *v % proof.domain_size
    }).collect::<Vec<usize>>();

    // check with proof challenge list
    if proof.challenge_list.len() != new_challenge_list.len() {
        return Err(String::from("Proof challenge list is incorrect."));
    } else {
        for (a, b) in proof.challenge_list.iter().zip(new_challenge_list.iter()) {
            if a != b {
                return Err(String::from("Proof challenge list is incorrect."));
            }
        }
    }

    // verify each query
    for (challenge, decommitment)  in new_challenge_list.iter().zip(proof.decommitment_list.iter()) {
        let check = verify_query(challenge, decommitment, &random_r_list, proof.domain_size, &proof.const_val, &proof.coset);
        if check.is_err() {
            return check;
        }
    }
    Ok(())
}


fn verify_query<F: PrimeField>(challenge: &usize, decommitment: &Decommitment<F>, random_r_list: &Vec<F>, domain_size: usize, const_val: &F, coset: &F) -> Result<(), String> {

    let mut cur_domain_size = domain_size.clone();
    let mut cur_coset = coset.clone();
    let two = F::from(2 as u128);

    for (((((i, eval), path), sym_eval), sym_path), random_r) in decommitment.evaluations.iter().enumerate()
        .zip(decommitment.auth_paths.iter())
        .zip(decommitment.sym_evaluations.iter())
        .zip(decommitment.sym_auth_paths.iter())
        .zip(random_r_list.iter()) {

        let index = challenge % cur_domain_size;
        let sym_index = (index + cur_domain_size / 2) % cur_domain_size;

        let cur_domain = <GeneralEvaluationDomain<F>>::new(cur_domain_size).unwrap();
        let w_i = cur_domain.element(index) * cur_coset;


        // verify path of merkle root
        if index != path.index || sym_index != sym_path.index {
            return Err(String::from("wrong index!"));
        }
        if *eval != path.leaf_val || *sym_eval != sym_path.leaf_val {
            return Err(String::from("evaluation does not correspond to path!"));
        }
        if !verify_merkle_proof(path) || !verify_merkle_proof(sym_path) {
            return Err(String::from("verify Merkle path failed!"));
        }


        // verify folding
        // let q_fold = (*eval + sym_eval) / two + (*random_r * (*eval - sym_eval)/(two * w_i)); : Another way to compute q_fold
        let q_fold = (*random_r + w_i) * eval / (two * w_i) - (*random_r - w_i) * sym_eval / (two * w_i);

        if i == decommitment.evaluations.len() - 1 { // end of the folding process, the result must be equal to constant value
            if q_fold != *const_val {
                return Err(String::from("folding wrong!"));
            }
        } else {
            let next_layer_evaluation = decommitment.evaluations[i + 1];
            if q_fold != next_layer_evaluation {
                return Err(String::from("folding wrong!"));
            }
        }
        cur_domain_size /= 2;
        cur_coset = cur_coset.square();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ark_ff::{FftField, Field};
    use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial};
    use ark_poly::univariate::DensePolynomial;
    use super::*;
    use crate::{fields::goldilocks::Fq};
    use crate::merkle_tree::MerkleTree;
    use crate::prover::{fold_polynomial, generate_proof};

    #[test]
    fn test_verifier() {
        let coef = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coef);

        let blowup_factor: usize = 2;
        let number_of_queries: usize = 2;
        let proof = generate_proof(&poly, blowup_factor, number_of_queries);
        // println!("Decommitment: {:?}", proof.decommitment_list);
        let result = verify(proof);
        //println!("{:?}", result.clone().unwrap());
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn test_verifier2() {
        let coef = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4), Fq::from(5), Fq::from(6)];
        let poly = DensePolynomial::from_coefficients_vec(coef);

        let blowup_factor: usize = 2;
        let number_of_queries: usize = 2;
        let proof = generate_proof(&poly, blowup_factor, number_of_queries);
        // println!("Decommitment: {:?}", proof.decommitment_list);
        let result = verify(proof);
        //println!("{:?}", result.clone().unwrap());
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    #[should_panic]
    fn test_verifier3() {
        let coef = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coef);

        let blowup_factor: usize = 2;
        let number_of_queries: usize = 2;
        let proof = generate_proof(&poly, blowup_factor, number_of_queries);

        let mut tmp = proof.clone();
        tmp.const_val -= Fq::from(1);
        let result = verify(tmp);
        assert_eq!(result.is_ok(), true);
    }

}
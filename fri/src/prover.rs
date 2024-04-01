use ark_ff::PrimeField;
use ark_poly::{DenseUVPolynomial};
use ark_poly::univariate::DensePolynomial;
use crate::fiat_shamir::Transcript;
use crate::fri_layer::FriLayer;
use crate::merkle_tree::MerkleProof;

#[derive(Clone, Debug)]
pub struct Decommitment<F: PrimeField> {
    pub evaluations: Vec<F>, // List of evaluation for each query index in all layers,
    pub auth_paths:Vec<MerkleProof<F>>, // and their authentication path in Merkle Tree
    pub sym_evaluations: Vec<F>, // List of evaluation for each symmetric query index in all layers,
    pub sym_auth_paths: Vec<MerkleProof<F>>, // and their authentication path in Merkle Tree
}

pub fn fold_polynomial<F: PrimeField>(
    poly: &DensePolynomial<F>,
    random_r: &F,
) -> DensePolynomial<F>{
    let coef = poly.clone().coeffs;
    let even_coef = coef.iter().step_by(2).cloned().collect();
    let odd_coef: Vec<F> = coef.iter().skip(1).step_by(2).cloned().collect();
    let odd_coef_mul_r = odd_coef.iter().map(|v| (*v * *random_r)).collect();

    let even_poly = DensePolynomial::from_coefficients_vec(even_coef);
    let odd_poly  =DensePolynomial::from_coefficients_vec(odd_coef_mul_r);
    even_poly + odd_poly
}

pub fn commit_phase<F: PrimeField>(
    p_0: &DensePolynomial<F>,
    coset: &F,
    domain_size: usize,
    number_layers: usize
) -> (F, Transcript<F>, Vec<FriLayer<F>>) {
    let mut fri_layers = Vec::new();
    let mut cur_domain_size = domain_size.clone();
    let mut cur_poly = p_0.clone();
    let mut cur_coset = coset.clone();
    let mut transcript = Transcript::new();
    let mut current_layer = FriLayer::new(&cur_poly, &cur_coset, cur_domain_size);
    fri_layers.push(current_layer.clone());
    transcript.append(current_layer.merkle_tree.root.clone());

    for i in 1..number_layers {
        let random_r = transcript.generate_a_challenge();
        cur_coset = cur_coset.square();
        cur_domain_size /= 2;

        // folding
        cur_poly = fold_polynomial(&cur_poly, &random_r);
        current_layer = FriLayer::new(&cur_poly, &cur_coset, cur_domain_size);
        fri_layers.push(current_layer.clone());
        transcript.append(current_layer.merkle_tree.root.clone());
    }

    // the constant commitment
    let random_r = transcript.generate_a_challenge();
    let last_poly = fold_polynomial(&cur_poly, &random_r);
    let const_value = last_poly.coeffs.get(0).unwrap_or(&F::ZERO).clone();

    transcript.append(const_value.clone());
    (const_value, transcript, fri_layers)
}


pub fn query_phase<F: PrimeField>(
    number_of_queries: usize,
    domain_size: usize,
    transcript: &Transcript<F>,
    fri_layers: &Vec<FriLayer<F>>
) -> (Vec<Decommitment<F>>, Vec<usize>) {
    if !fri_layers.is_empty() {
        let challenge_list = transcript.generate_index_list(number_of_queries).iter().map(|v| {
            *v % domain_size
        }).collect::<Vec<usize>>();

        let mut decommitment_list = Vec::new();

        for challenge in challenge_list.clone() {
            let mut evaluations = vec![];
            let mut sym_evaluations = vec![];
            let mut auth_paths = vec![];
            let mut sym_auth_paths = vec![];

            for layer in fri_layers {
                let index = challenge % layer.domain_size;
                let sym_index = (index + layer.domain_size / 2) % layer.domain_size;

                let evaluation = layer.evaluations[index].clone();
                let sym_evaluation = layer.evaluations[sym_index].clone();

                let auth_path = layer.merkle_tree.generate_proof(index);
                let sym_auth_path = layer.merkle_tree.generate_proof(sym_index);

                evaluations.push(evaluation);
                sym_evaluations.push(sym_evaluation);

                auth_paths.push(auth_path);
                sym_auth_paths.push(sym_auth_path);
            }

            let cur_decommitment = Decommitment {
                evaluations,
                auth_paths,
                sym_evaluations,
                sym_auth_paths
            };
            decommitment_list.push(cur_decommitment);
        }

        (decommitment_list, challenge_list)
    } else {
        (vec![], vec![])
    }
}



#[cfg(test)]
mod tests {
    use ark_ff::FftField;
    use ark_poly::DenseUVPolynomial;
    use ark_poly::univariate::DensePolynomial;
    use crate::{fields::goldilocks::Fq};
    use crate::merkle_tree::{MerkleTree, verify_merkle_proof};
    use crate::prover::{commit_phase, fold_polynomial, query_phase};

    #[test]
    fn test_fold_polynomial() {
        let coef = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coef);
        let random_r = Fq::from(1);
        let folded_poly = fold_polynomial::<Fq>(&poly, &random_r);
        println!("{:?}", folded_poly);
        let res_coef = vec![Fq::from(3), Fq::from(7)];
        assert_eq!(folded_poly, DensePolynomial::from_coefficients_vec(res_coef));
    }

    #[test]
    fn test_commit_phase() {
        let coef = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coef);
        let number_of_layers :usize = 2;
        let coset = Fq::GENERATOR;
        println!("{:?}", coset);
        let (const_val,transcript, fri_layers) = commit_phase(&poly, &coset, 4, number_of_layers);
        println!("{:?}", const_val);

        assert_eq!(const_val, Fq::from(10));
        assert_eq!(fri_layers[1].coset, Fq::from(49));
        assert_eq!(fri_layers[1].domain_size, 2);
    }

    #[test]
    fn test_query_phase() {
        let coef = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coef);
        let number_of_layers :usize = 2;
        let coset = Fq::GENERATOR;
        let (const_val, transcript, fri_layers) = commit_phase(&poly, &coset, 4, number_of_layers);
        let (decommitment_list, challenge_list) = query_phase(1, 4, &transcript, &fri_layers);
        println!("{:?}", fri_layers.len());
        let validate_challenge_list = transcript.generate_index_list(1).iter().map(|v| {
            *v % 4
        }).collect::<Vec<usize>>();
        println!("{:?}", challenge_list);

        assert_eq!(validate_challenge_list, challenge_list);
        println!("len: {:?}", decommitment_list.len());
        let decommitment = decommitment_list[0].clone();
        println!("{:?}", decommitment);
        let auth_paths_layer2 = decommitment.auth_paths[0].index;
        let sym_auth_paths_layer2 = decommitment.sym_auth_paths[0].index;
        assert_eq!(auth_paths_layer2, 1);
        assert_eq!(auth_paths_layer2 + 2, sym_auth_paths_layer2);

    }


}
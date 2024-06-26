use crate::fiat_shamir::transcript::Transcript;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial};
use sha2::Digest;
use std::ops::Mul;

use crate::fri_layer::FriLayer;
use crate::merkle_tree::MerkleProof;

#[derive(Clone, Debug)]
pub struct Decommitment<F: PrimeField> {
    pub evaluations: Vec<F>,
    // A list of evaluations for each query index in all layers,
    pub auth_paths: Vec<MerkleProof<F>>,
    // and their authentication paths in Merkle Tree
    pub sym_evaluations: Vec<F>,
    // A list of evaluation for each symmetric query index in all layers,
    pub sym_auth_paths: Vec<MerkleProof<F>>, // and their authentication paths in Merkle Tree
}

#[derive(Clone, Debug)]
pub struct Proof<F: PrimeField> {
    pub domain_size: usize,
    pub coset: F,
    pub number_of_queries: usize,
    pub layers_root: Vec<F>,
    pub const_val: F,
    pub decommitment_list: Vec<Decommitment<F>>,
    // pub challenge_list: Vec<usize>
}

/// Reduce the power in half with formula new_coeff = even_coeff + `random_r` * odd_coeff
fn fold_polynomial<F: PrimeField>(poly: &DensePolynomial<F>, random_r: F) -> DensePolynomial<F> {
    let coeff = poly.coeffs.clone();
    let even_coeff = coeff.iter().step_by(2).cloned().collect();
    let odd_coeff_mul_r: Vec<F> = coeff.into_iter().skip(1).step_by(2).collect();

    let even_poly = DensePolynomial::from_coefficients_vec(even_coeff);
    let odd_poly = DensePolynomial::from_coefficients_vec(odd_coeff_mul_r);
    even_poly + odd_poly.mul(random_r)
}

/// Verify that `poly` have degree `k` or `number_layers`
///
/// Also create prove for the evaluation of the polynomial
fn folding_phase<T: Digest + Default, F: PrimeField>(
    mut poly: DensePolynomial<F>,
    mut coset: F,
    mut domain_size: usize,
    number_layers: usize,
) -> (F, Transcript<T, F>, Vec<FriLayer<F>>) {
    let mut fri_layers: Vec<FriLayer<F>> = Vec::with_capacity(number_layers.ilog2() as usize + 1);
    let mut transcript = Transcript::new(F::ZERO);

    for _ in 0..number_layers {
        let current_layer = FriLayer::from_poly(&poly, coset, domain_size);
        transcript.digest(current_layer.merkle_tree.root());
        eprintln!(
            "current_layer.merkle_tree.root() = {:#?}",
            current_layer.merkle_tree.root()
        );
        fri_layers.push(current_layer);

        poly = fold_polynomial(&poly, transcript.generate_a_challenge());
        coset = coset.square();
        domain_size /= 2;
    }

    assert_eq!(poly.len(), 1);
    let constant = poly.evaluate(&F::ZERO);
    transcript.digest(constant);

    (constant, transcript, fri_layers)
}

/// Create proof that prover did the folding phase correctly
///
/// Evaluate current polynomial q(x) at two random symmetric point x1, x2 in subset Omega and
/// verify if the next step is the result of a 1st degree polynomial of random_r with q(x1) and q(x2)
fn query_phase<T: Digest + Default, F: PrimeField>(
    number_of_queries: usize,
    domain_size: usize,
    transcript: &mut Transcript<T, F>,
    fri_layers: &Vec<FriLayer<F>>,
) -> (Vec<Decommitment<F>>, Vec<usize>) {
    if fri_layers.is_empty() {
        return (vec![], vec![]);
    }

    let challenge_list = transcript
        .generate_challenge_list_usize(number_of_queries)
        .iter()
        .map(|v| *v % domain_size)
        .collect::<Vec<_>>();

    let mut decommitment_list = Vec::new();

    for challenge in challenge_list.clone() {
        // generate decommitment for each challenge.
        let mut evaluations = vec![];
        let mut sym_evaluations = vec![];
        let mut auth_paths = vec![];
        let mut sym_auth_paths = vec![];

        for layer in fri_layers {
            // index and sym_index will be symmetric of each other in layer.domain_size finite field
            let index = challenge % layer.domain_size;
            let sym_index = (index + layer.domain_size / 2) % layer.domain_size;

            let evaluation = layer.evaluations[index];
            let sym_evaluation = layer.evaluations[sym_index];

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
            sym_auth_paths,
        };
        decommitment_list.push(cur_decommitment);
    }

    (decommitment_list, challenge_list)
}

/// Generate a proof of FRI prover by going through 2 phase
///
/// Folding phase and query phase
///
/// This is the only method you should call for proving
pub fn generate_proof<T: Digest + Default, F: PrimeField>(
    poly: DensePolynomial<F>,
    blowup_factor: usize,
    number_of_queries: usize,
) -> Proof<F> {
    let domain_size = (poly.coeffs.len() * blowup_factor).next_power_of_two();
    let coset = F::GENERATOR;
    let number_of_layers = domain_size.ilog2() as usize;

    let (const_val, mut transcript, fri_layers) =
        folding_phase::<T, F>(poly, coset, domain_size, number_of_layers);
    let (decommitment_list, _) =
        query_phase(number_of_queries, domain_size, &mut transcript, &fri_layers);

    let layers_root: Vec<F> = fri_layers
        .into_iter()
        .map(|layer| layer.merkle_tree.root())
        .collect();

    Proof {
        domain_size,
        coset,
        number_of_queries,
        layers_root,
        const_val,
        decommitment_list,
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::FftField;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::DenseUVPolynomial;
    use sha2::Sha256;

    use crate::fields::goldilocks::Fq;
    use crate::prover::{fold_polynomial, folding_phase, query_phase};

    #[test]
    fn test_fold_polynomial() {
        let coeff = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coeff);
        let random_r = Fq::from(1);
        let folded_poly = fold_polynomial::<Fq>(&poly, random_r);

        let res_coeff = vec![Fq::from(3), Fq::from(7)];
        assert_eq!(
            folded_poly,
            DensePolynomial::from_coefficients_vec(res_coeff)
        );
    }

    #[test]
    fn test_commit_phase() {
        let coeff = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coeff);
        let number_of_layers: usize = 2;
        let coset = Fq::GENERATOR;
        let (_const_val, _transcript, fri_layers) =
            folding_phase::<Sha256, Fq>(poly, coset, 4, number_of_layers);

        assert_eq!(fri_layers[1].coset, Fq::from(49));
        assert_eq!(fri_layers[1].domain_size, 2);
    }

    #[test]
    fn test_query_phase() {
        let domain_size = 4;
        let coeff = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];
        let poly = DensePolynomial::from_coefficients_vec(coeff);
        let number_of_layers: usize = 2;
        let coset = Fq::GENERATOR;
        let (_const_val, mut transcript, fri_layers) =
            folding_phase::<Sha256, Fq>(poly, coset, domain_size, number_of_layers);
        let (decommitment_list, _) = query_phase(1, domain_size, &mut transcript, &fri_layers);
        let decommitment = decommitment_list[0].clone();
        let auth_paths_layer2 = decommitment.auth_paths[0].index;
        let sym_auth_paths_layer2 = decommitment.sym_auth_paths[0].index;
        assert_eq!((auth_paths_layer2 + 2) % domain_size, sym_auth_paths_layer2);
    }
}

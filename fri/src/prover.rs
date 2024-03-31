use ark_ff::PrimeField;
use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DensePolynomial;
use crate::fiat_shamir::Transcript;
use crate::fri_layer::FriLayer;

pub struct Decommitment {

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
) -> (F, Vec<FriLayer<F>>) {
    let mut fri_layers = Vec::new();
    let mut cur_domain_size = domain_size.clone();
    let mut cur_poly = p_0.clone();
    let mut cur_coset = coset.clone();
    let mut transcript = Transcript::new();
    let mut current_layer = FriLayer::new(&cur_poly, &cur_coset, cur_domain_size);
    fri_layers.push(current_layer.clone());
    transcript.append(&current_layer.merkle_tree.root);

    for i in 1..number_layers {
        let random_r = transcript.generate_a_challenge();
        cur_coset = cur_coset.square();
        cur_domain_size /= 2;

        // folding
        cur_poly = fold_polynomial(&cur_poly, &random_r);
        current_layer = FriLayer::new(&cur_poly, &cur_coset, cur_domain_size);
        fri_layers.push(current_layer.clone());
        transcript.append(&current_layer.merkle_tree.root);
    }

    // the constant commitment
    let random_r = transcript.generate_a_challenge();
    let last_poly = fold_polynomial(&cur_poly, &random_r);
    let const_value = last_poly.coeffs.get(0).unwrap_or(&F::ZERO).clone();

    transcript.append(&const_value);
    (const_value, fri_layers)
}






#[cfg(test)]
mod tests {
    use ark_poly::DenseUVPolynomial;
    use ark_poly::univariate::DensePolynomial;
    use crate::{fields::goldilocks::Fq};
    use crate::merkle_tree::{MerkleTree, verify_merkle_proof};
    use crate::prover::fold_polynomial;

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
}
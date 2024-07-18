use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use sha2::Sha256;

use fri::fields::goldilocks::Fq;
use fri::prover::generate_proof;
use fri::verifier::verify;

fn main() {
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
    println!("Generate proof...");
    let proof = generate_proof::<Sha256, Fq>(poly, blowup_factor, number_of_queries);
    println!("Verify....");
    let result = verify::<Sha256, Fq>(proof);

    assert!(result.is_ok());
    println!("Accepted!");
}

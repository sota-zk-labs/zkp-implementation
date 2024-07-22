use ark_bls12_381::Fr;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial};
use kzg::scheme::KzgScheme;
use kzg::srs::Srs;

fn main() {
    // trusted setup
    let srs = Srs::new(10);
    let scheme = KzgScheme::new(srs);

    // polynomial x^3 + 3x + 5

    let coeff = vec![Fr::from(5), Fr::from(3), Fr::from(0), Fr::from(1)];
    let poly = DensePolynomial::from_coefficients_vec(coeff);
    let v = poly.evaluate(&Fr::from(1));
    assert_eq!(v, Fr::from(9));

    // commit poly
    let commitment = scheme.commit(&poly);
    // opening point at p = 4.
    let opening_pos = Fr::from(4);
    let opening = scheme.open(&poly, opening_pos);

    assert!(scheme.verify(&commitment, &opening, opening_pos));
}

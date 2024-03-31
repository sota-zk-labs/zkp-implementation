use ark_ff::PrimeField;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};

pub fn fold_polynomial<F:PrimeField>(polynomial: DensePolynomial<F>, rand: F) ->DensePolynomial<F> {
    let mut folded_coeffs: Vec<F> = Vec::new();
    for i in (0..polynomial.coeffs.len()).step_by(reduction) {
        let mut sum = F::ZERO;
        for j in (0..2).rev() {
            sum = sum * rand + polynomial.coeffs[i+j];
        }
        folded_coeffs.push(sum);
    }
    DenseUVPolynomial::from_coefficients_vec(folded_coeffs)
}


use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;

pub type Poly<F: PrimeField> = DensePolynomial<F>;
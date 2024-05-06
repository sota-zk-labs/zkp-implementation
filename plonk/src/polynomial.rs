use std::ops::Add;

use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;

pub trait IntoPolynomialExt<T: Field> {
    fn into_polynomial(self) -> DensePolynomial<T>;
}

impl<Fr: Field> IntoPolynomialExt<Fr> for Fr {
    fn into_polynomial(self) -> DensePolynomial<Fr> {
        DensePolynomial::from_coefficients_vec(vec![self])
    }
}

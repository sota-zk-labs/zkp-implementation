use std::ops::Mul;

use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_poly::univariate::SparsePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial as Poly};

use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;

use crate::types::Polynomial;

#[derive(Debug)]
pub(crate) struct SlicePoly {
    slices: [Polynomial; 3],
    degree: usize,
}

impl SlicePoly {
    pub fn new(polynomial: Polynomial, degree: usize) -> Self {
        assert!(polynomial.degree() <= 3 * degree + 5);
        let coefficients = polynomial.coeffs;

        let mut tmp = coefficients.len() / 3;
        if tmp * 3 < coefficients.len() {
            tmp += 1;
        }

        let mut slices = [(); 3].map(|_| Polynomial::zero());
        coefficients
            .chunks(tmp)
            .map(|coeffs| Polynomial::from_coefficients_slice(coeffs))
            .enumerate()
            .for_each(|(index, slice)| {
                slices[index] = slice;
            });

        Self {
            slices,
            degree: (tmp - 1),
        }
    }

    pub fn get_degree(&self) -> usize {
        self.degree
    }

    pub fn commit(&self, scheme: &KzgScheme) -> [KzgCommitment; 3] {
        self.slices.clone().map(|slice| scheme.commit(&slice))
    }

    pub fn compact(&self, point: &Fr) -> Polynomial {
        self.slices
            .iter()
            .enumerate()
            .map(|(index, slice)| {
                let exponent = SparsePolynomial::from_coefficients_slice(&[(
                    (self.degree + 1) * index,
                    Fr::one(),
                )]);
                slice.mul(exponent.evaluate(point))
            })
            .reduce(|one, other| one + other)
            .unwrap()
    }
}

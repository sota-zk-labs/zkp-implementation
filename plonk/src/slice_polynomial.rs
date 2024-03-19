use std::ops::Mul;

use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_poly::{Polynomial as Poly, UVPolynomial};
use ark_poly::univariate::SparsePolynomial;

use kzg::{KzgCommitment, KzgScheme};

use crate::Polynomial;

#[derive(Debug)]
pub(crate) struct SlidePoly {
    slices: [Polynomial; 3],
    degree: usize,
}

impl SlidePoly {
    pub fn new(polynomial: Polynomial, degree: usize) -> Self {
        assert!(polynomial.degree() <= 3 * degree + 5);
        let coeffs = polynomial.coeffs;

        let mut tmp = coeffs.len() / 3;
        if tmp * 3 < coeffs.len() {
            tmp += 1;
        }

        let mut slices = [(); 3].map(|_| Polynomial::zero());
        coeffs
            .chunks(tmp)
            .map(|coeffs| Polynomial::from_coefficients_slice(coeffs))
            .enumerate()
            .for_each(|(index, slice)| {
                slices[index] = slice;
            });

        Self { slices, degree: (tmp - 1) }
    }

    pub fn get_degree(&self) -> usize {
        self.degree.clone()
    }

    // pub fn get_slices(&self) -> &[Polynomial; 3] {
    //     &self.slices
    // }
    pub fn commit(&self, scheme: &KzgScheme) -> [KzgCommitment; 3] {
        self.slices.clone().map(|slice| scheme.commit(&slice))
    }

    pub fn compact(&self, point: &Fr) -> Polynomial {
        self.slices.iter().enumerate().map(|(index, slice)| {
            let exponent = SparsePolynomial::from_coefficients_slice(&[(
                (self.degree + 1) * index,
                Fr::one(),
            )]);
            slice.mul(exponent.evaluate(&point))
        }).reduce(|one, other| one + other).unwrap()
    }
}
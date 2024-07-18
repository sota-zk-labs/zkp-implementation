use std::ops::Mul;

use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_poly::univariate::SparsePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial as Poly};

use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;

use crate::types::Polynomial;

/// Struct representing a slice polynomial.
#[derive(Debug)]
pub(crate) struct SlicePoly {
    slices: [Polynomial; 3],
    degree: usize,
}

impl SlicePoly {
    /// Creates a new slice polynomial with the given polynomial and degree.
    pub fn new(polynomial: Polynomial) -> Self {
        let coefficients = polynomial.coeffs;

        let mut tmp = coefficients.len() / 3;
        if tmp * 3 < coefficients.len() {
            tmp += 1;
        }

        let mut slices = [(); 3].map(|_| Polynomial::zero());
        coefficients
            .chunks(tmp)
            .map(Polynomial::from_coefficients_slice)
            .enumerate()
            .for_each(|(index, slice)| {
                slices[index] = slice;
            });

        Self {
            slices,
            degree: (tmp - 1),
        }
    }

    /// Gets the degree of the slice polynomial.
    pub fn get_degree(&self) -> usize {
        self.degree
    }

    /// Commits to each slice polynomial using the provided KZG scheme.
    pub fn commit(&self, scheme: &KzgScheme) -> [KzgCommitment; 3] {
        self.slices.clone().map(|slice| scheme.commit(&slice))
    }

    /// Compacts the slice polynomial at the given point.
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

#[cfg(test)]
mod tests {
    use ark_ff::{Field, UniformRand};
    use ark_std::test_rng;

    use super::*;

    #[test]
    fn test_slice_poly() {
        let rng = &mut test_rng();
        let degree = 3;
        let coeffs: Vec<Fr> = (0..12).map(|_| Fr::rand(rng)).collect();
        let poly = Polynomial::from_coefficients_vec(coeffs.clone());

        let slice_poly = SlicePoly::new(poly.clone());
        assert_eq!(slice_poly.get_degree(), degree);

        // Test the slices
        for (i, slice) in slice_poly.slices.iter().enumerate() {
            let expected_coeffs = &coeffs[i * (degree + 1)..(i + 1) * (degree + 1)];
            assert_eq!(slice.coeffs(), expected_coeffs);
        }

        // Test compacting the polynomial
        let point = Fr::rand(rng);
        let compacted_poly = slice_poly.compact(&point);
        let expected_poly = (0..3)
            .map(|i| {
                let exp = (degree + 1) * i;
                let coeff = point.pow([exp as u64]);
                Polynomial::from_coefficients_slice(
                    &coeffs[i * (degree + 1)..(i + 1) * (degree + 1)],
                )
                .mul(coeff)
            })
            .reduce(|a, b| a + b)
            .unwrap();

        assert_eq!(compacted_poly, expected_poly);
    }
}

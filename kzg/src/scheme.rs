use std::fmt::{Debug, Display};
use std::ops::{Add, Mul, Neg, Sub};

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly::{DenseUVPolynomial, Polynomial};

use crate::commitment::KzgCommitment;
use crate::opening::KzgOpening;
use crate::srs::Srs;
use crate::types::{G1Point, Poly};

/// Implements the KZG polynomial commitment scheme.
///
/// The `KzgScheme` struct provides methods for committing to polynomials, opening commitments,
/// and verifying openings.
pub struct KzgScheme(Srs);

impl KzgScheme {
    /// Creates a new instance of `KzgScheme` with the given structured reference string (SRS).
    ///
    /// # Parameters
    ///
    /// - `srs`: The structured reference string (SRS) used in the scheme.
    ///
    /// # Returns
    ///
    /// A new instance of `KzgScheme`.
    pub fn new(srs: Srs) -> Self {
        Self(srs)
    }
}

impl KzgScheme {
    /// Commits to a polynomial using the KZG scheme.
    ///
    /// # Parameters
    ///
    /// - `polynomial`: The polynomial to be committed to.
    ///
    /// # Returns
    ///
    /// The commitment to the polynomial.
    pub fn commit(&self, polynomial: &Poly) -> KzgCommitment {
        let commitment = self.evaluate_in_s(polynomial);
        KzgCommitment(commitment)
    }

    /// Commits to a parameter using the KZG scheme.
    ///
    /// # Parameters
    ///
    /// - `para`: The parameter to be committed to.
    ///
    /// # Returns
    ///
    /// The commitment to the parameter.
    pub fn commit_para(&self, para: Fr) -> KzgCommitment {
        let g1_0 = *self.0.g1_points().first().unwrap();
        let commitment = g1_0.mul(para).into();
        KzgCommitment(commitment)
    }

    fn evaluate_in_s(&self, polynomial: &Poly) -> G1Point {
        let g1_points = self.0.g1_points();
        assert!(g1_points.len() > polynomial.degree());

        let poly = polynomial.coeffs.iter();
        let g1_points = g1_points.into_iter();
        let point: G1Point = poly
            .zip(g1_points)
            .map(|(cof, s)| s.mul(cof).into_affine())
            .reduce(|acc, e| acc.add(e).into_affine())
            .unwrap_or(G1Point::zero());
        point
    }

    /// Opens a commitment at a specified point.
    ///
    /// # Parameters
    ///
    /// - `polynomial`: The polynomial to be opened.
    /// - `z`: The point at which the polynomial is opened.
    ///
    /// # Returns
    ///
    /// The opening at the specified point.
    pub fn open(&self, mut polynomial: Poly, z: impl Into<Fr>) -> KzgOpening {
        let z = z.into();
        let evaluation_at_z = polynomial.evaluate(&z);
        let first = polynomial.coeffs.first_mut().expect("at least 1");
        *first -= evaluation_at_z;
        let root = Poly::from_coefficients_slice(&[-z, 1.into()]);
        let new_poly = &polynomial / &root;
        let opening = self.evaluate_in_s(&new_poly);

        KzgOpening(opening, evaluation_at_z)
    }

    /// Verifies the correctness of an opening.
    ///
    /// # Parameters
    ///
    /// - `commitment`: The commitment to be verified.
    /// - `opening`: The opening to be verified.
    /// - `z`: The point at which the polynomial was opened.
    ///
    /// # Returns
    ///
    /// `true` if the opening is valid, otherwise `false`.
    pub fn verify(
        &self,
        commitment: &KzgCommitment,
        opening: &KzgOpening,
        z: impl Into<Fr> + Debug + Display,
    ) -> bool {
        let y = opening.1;
        let g2s = self.0.g2s();
        let g2 = self.0.g2();
        let a = g2s.sub(g2.mul(z.into()).into_affine());
        let b = commitment.0.sub(G1Point::generator().mul(y).into_affine());
        let pairing1 = Bls12_381::pairing(opening.0, a);
        let pairing2 = Bls12_381::pairing(b, g2);
        pairing1 == pairing2
    }
}

impl Add for KzgCommitment {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let commitment = self.0 + rhs.0;
        Self(commitment.into())
    }
}

impl Sub for KzgCommitment {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::add(self, -rhs)
    }
}

impl Mul<Fr> for KzgCommitment {
    type Output = Self;

    fn mul(self, rhs: Fr) -> Self::Output {
        let element = self.0.mul(rhs);
        Self(element.into())
    }
}

impl Mul<Fr> for &KzgCommitment {
    type Output = KzgCommitment;

    fn mul(self, rhs: Fr) -> Self::Output {
        let element = self.0.mul(rhs);
        KzgCommitment(element.into())
    }
}

impl Neg for KzgCommitment {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let point = self.0;
        Self(-point)
    }
}

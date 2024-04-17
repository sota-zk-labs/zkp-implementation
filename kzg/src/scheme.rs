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

/// KzgScheme, Srs: structured reference string
pub struct KzgScheme(Srs);

impl KzgScheme {
    pub fn new(srs: Srs) -> Self {
        Self(srs)
    }
}

impl KzgScheme {
    pub fn commit(&self, polynomial: &Poly) -> KzgCommitment {
        let commitment = self.evaluate_in_s(polynomial);
        KzgCommitment(commitment)
    }

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

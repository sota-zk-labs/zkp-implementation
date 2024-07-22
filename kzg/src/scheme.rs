use std::fmt::{Debug, Display};
use std::ops::{Add, Mul, Neg, Sub};

use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial};
use rand::{Rng, RngCore};

use crate::commitment::KzgCommitment;
use crate::opening::KzgOpening;
use crate::srs::Srs;
use crate::types::{G1Point, Poly, ScalarField};

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

    /// Commits to a coefficient vector using the KZG scheme.
    ///
    /// # Parameters
    ///
    /// - `coeffs`: The coefficient vector to be committed to.
    ///
    /// # Returns
    ///
    /// The commitment to the polynomial.
    pub fn commit_vector(&self, coeffs: &[ScalarField]) -> KzgCommitment {
        let new_poly = DensePolynomial::from_coefficients_vec(coeffs.into());
        let commitment = self.evaluate_in_s(&new_poly);
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
    pub fn open(&self, polynomial: &Poly, z: impl Into<Fr>) -> KzgOpening {
        let z = z.into();
        let evaluation_at_z = polynomial.evaluate(&z);
        let mut new_poly = polynomial.clone();
        let first = new_poly.coeffs.first_mut().expect("at least 1");
        *first -= evaluation_at_z;
        let root = Poly::from_coefficients_slice(&[-z, 1.into()]);
        // quotient polynomial
        let quotient_poly = &new_poly / &root;
        let opening = self.evaluate_in_s(&quotient_poly);

        KzgOpening(opening, evaluation_at_z)
    }

    /// Opens a commitment at a specified point.
    ///
    /// # Parameters
    ///
    /// - `coeffs`: The coefficient vector to be opened.
    /// - `z`: The point at which the polynomial is opened.
    ///
    /// # Returns
    ///
    /// The opening at the specified point.
    pub fn open_vector(&self, coeffs: &[ScalarField], z: impl Into<Fr>) -> KzgOpening {
        let z = z.into();
        let mut polynomial = DensePolynomial::from_coefficients_vec(coeffs.into());
        let evaluation_at_z = polynomial.evaluate(&z);
        let first = polynomial.coeffs.first_mut().expect("at least 1");
        *first -= evaluation_at_z;
        let root = Poly::from_coefficients_slice(&[-z, 1.into()]);
        let quotient_poly = &polynomial / &root;
        let opening = self.evaluate_in_s(&quotient_poly);
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
        // e([Q]_1, [x]_2 - G_2 ⋅ z)
        let pairing1 = Bls12_381::pairing(opening.0, a);
        // e([P]_1 - G_1 ⋅ P(x), G_2)
        let pairing2 = Bls12_381::pairing(b, g2);
        pairing1 == pairing2
    }

    /// Aggregates multiple commitments into one commitment using a random challenge
    ///
    /// For some challenge `v`, a list of commitments `(c_0, c_1, ... c_n) `
    ///
    /// We compute the aggregate commitment as `v^0 * c_0 + v^1 * c_1 + ...+ v^n * c_n`
    ///
    /// # Arguments
    ///
    /// * `commitments`: The commitments to be aggregated
    /// * `challenge`: The random challenge
    ///
    /// # Returns
    ///
    /// Aggregated commitment from input commitments
    pub fn aggregate_commitments(
        commitments: &Vec<&KzgCommitment>,
        challenge: &Fr,
    ) -> KzgCommitment {
        let mut pow = Fr::one();
        let mut result = G1Projective::zero();

        for commitment in commitments {
            result += &commitment.0.mul(pow);
            pow *= challenge;
        }

        KzgCommitment(result.into_affine())
    }

    /// Verifies that each proof is a valid proof of evaluation for `commitment_i` at `point_i`.
    ///
    /// This function is implemented according to the protocol on page 13 of the Plonk paper,
    ///
    /// # Arguments
    ///
    /// * `commitments`: The polynomials' commitments that need to be verified
    /// * `points`: The corresponding challenge points
    /// * `openings`: The corresponding open proof for polynomials
    ///
    /// # Returns
    ///
    /// `true` if all proofs is valid, otherwise `false`.
    pub fn batch_verify(
        &self,
        commitments: &[KzgCommitment],
        points: &[Fr],
        openings: &[KzgOpening],
        rng: &mut impl RngCore,
    ) -> bool {
        assert_eq!(commitments.len(), points.len());
        assert_eq!(openings.len(), points.len());

        let g1 = G1Point::generator();
        let mut e_1 = G1Point::zero();
        let mut e_2 = G1Point::zero();

        for ((cm, z), KzgOpening(w, s)) in commitments.iter().zip(points).zip(openings) {
            // cm_i - s_i
            let cm_minus_s = *cm.inner() - g1.mul(s).into_affine();
            // z_i * w_i
            let z_mul_w = *w * z;
            // r'
            let r_prime = Fr::from(rng.gen::<u128>());
            // e_1 += r_prime^i * (cm_i - s_i + z_i * w_i)
            e_1 = Affine::from(e_1 + (cm_minus_s + z_mul_w) * r_prime);

            // e_2 += r_prime^i * w_i;
            e_2 = Affine::from(e_2 + (*w * r_prime));
        }

        // check if e(e_1, [1]_2) = e(e_2, [x]_2)
        Bls12_381::pairing(e_1, self.0.g2()) == Bls12_381::pairing(e_2, self.0.g2s())
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

use std::ops::Mul;

use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand};

use crate::types::{G1Point, G2Point};

/// Structured Reference String (SRS) used in the KZG scheme.
///
/// The `Srs` struct represents the structured reference string used in the KZG scheme,
/// containing precomputed values necessary for commitment and verification.
#[derive(Debug, Clone)]
pub struct Srs {
    /// Points in G1, each equals to generator point multiplied by the secret's powers.
    g1_points: Vec<G1Point>,
    /// Generator point in G2.
    g2: G2Point,
    /// Generator point in G2 multiplied by the secret.
    g2s_point: G2Point,
}

impl Srs {
    /// Generates a new SRS with a random secret and the specified circuit size.
    ///
    /// # Parameters
    ///
    /// - `circuit_size`: The size of the circuit.
    ///
    /// # Returns
    ///
    /// A new `Srs` instance.
    pub fn new(circuit_size: usize) -> Self {
        let s = Fr::rand(&mut rand::thread_rng());
        Self::new_from_secret(s, circuit_size)
    }

    /// Generates a new SRS with the provided secret and the specified circuit size.
    ///
    /// # Parameters
    ///
    /// - `secret`: The secret used for generating the SRS.
    /// - `circuit_size`: The size of the circuit.
    ///
    /// # Returns
    ///
    /// A new `Srs` instance.
    pub fn new_from_secret(secret: Fr, circuit_size: usize) -> Self {
        let g1 = G1Point::generator();

        let g1_points = vec![Fr::one(); circuit_size + 3];
        let mut cur = Fr::one();
        let g1_points = g1_points
            .into_iter()
            .map(|_| {
                let res = g1.mul(cur).into_affine();
                cur *= secret;
                res
            })
            .collect::<Vec<_>>();

        let g2 = G2Point::generator();
        let g2s_point = g2.mul(secret).into();
        Self {
            g1_points,
            g2,
            g2s_point,
        }
    }
}

impl Srs {
    /// Returns the precomputed points in G1.
    ///
    /// # Returns
    ///
    /// A vector containing points in G1.
    pub fn g1_points(&self) -> Vec<G1Point> {
        self.g1_points.clone()
    }

    /// Returns the generator point in G2.
    ///
    /// # Returns
    ///
    /// The generator point in G2.
    pub fn g2(&self) -> G2Point {
        self.g2
    }

    /// Returns the generator point in G2 multiplied by the secret.
    ///
    /// # Returns
    ///
    /// The generator point in G2 multiplied by the secret.
    pub fn g2s(&self) -> G2Point {
        self.g2s_point
    }
}

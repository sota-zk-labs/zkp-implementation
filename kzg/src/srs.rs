use std::ops::Mul;

use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::One;
use ark_ff::UniformRand;

use crate::types::{G1Point, G2Point};

/// Structured reference string
#[derive(Debug, Clone)]
pub struct Srs {
    /// G1 times the secret's powers
    g1_points: Vec<G1Point>,
    /// generator on G2
    g2: G2Point,
    /// generator on G2 times the secret
    g2s_point: G2Point,
}

impl Srs {
    /// generate
    pub fn new(circuit_size: usize) -> Self {
        let s = Fr::rand(&mut rand::thread_rng());
        Self::new_from_secret(s, circuit_size)
    }

    /// only use it for testing purposes
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
    pub fn g1_points(&self) -> Vec<G1Point> {
        self.g1_points.clone()
    }

    pub fn g2(&self) -> G2Point {
        self.g2
    }

    pub fn g2s(&self) -> G2Point {
        self.g2s_point
    }
}

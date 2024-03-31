use ark_bls12_381::Fr;
use ark_ec::AffineCurve;
use crate::{G1Point, G2Point};
use ark_ff::{One};
use ark_ff::UniformRand;
#[derive(Debug)]
pub struct Srs {
    g1: Vec<G1Point>,
    g2: G2Point,
    g2s: G2Point
}

impl Srs {
    // generate points
    pub fn new_from_secret(secret: Fr, gates: usize) -> Self{
        let g1 = Self::g1(secret, gates + 3);
        let (g2, g2s) = Self::g2(secret);
        Self {g1, g2, g2s}
    }

    fn g1(secret: Fr, len: usize) -> Vec<G1Point> {
        let generator = G1Point::prime_subgroup_generator();
        let mut srs = vec![];
        srs.push(generator);
        let mut cur = Fr::one();
        for _ in 1..len {
            cur = cur * secret;
            let tmp = generator.mul(cur).into();
            srs.push(tmp);
        }
        srs
    }

    fn g2(secret: Fr) -> (G2Point, G2Point) {
        let generator = G2Point::prime_subgroup_generator();
        let g2s = generator.mul(secret).into();
        (generator, g2s)
    }

    pub fn random(gates: usize) -> Self {
        let mut rng = rand::thread_rng();
        let s = Fr::rand(&mut rng);
        Self::new_from_secret(s, gates)
    }

    pub fn get_g1_ref(&self) -> &Vec<G1Point> {
        &self.g1
    }

    pub fn get_g2_ref(&self) -> &G2Point {
        &self.g2
    }

    pub fn get_g2s_ref(&self) -> &G2Point {
        &self.g2s
    }
}
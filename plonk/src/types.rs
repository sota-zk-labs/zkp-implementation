use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_poly::univariate::DensePolynomial;

pub type G1Point = G1Affine;
pub type G2Point = G2Affine;
pub type Polynomial = DensePolynomial<Fr>;

use ark_bls12_381::Fr;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;

pub type G1Point = <Bls12<ark_bls12_381::Config> as Pairing>::G1Affine;
pub type G2Point = <Bls12<ark_bls12_381::Config> as Pairing>::G2Affine;
pub type ScalarField = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField;
pub type Poly = DensePolynomial<Fr>;

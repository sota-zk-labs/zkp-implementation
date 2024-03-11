use ark_bls12_381::Fr;
use ark_ec::PairingEngine;
use ark_poly::{GeneralEvaluationDomain, univariate::DensePolynomial};

use kzg::srs::Srs;

use crate::constrain::{CopyConstraints, GateConstraints};

pub type G1Point = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Affine;
pub type G2Point = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Affine;
pub type Polynomial = DensePolynomial<Fr>;


mod circuit;
mod gate;
mod constrain;
mod prover;
mod challenge;
mod slice_polynomial;
mod errors;
mod verifier;

#[derive(Debug)]
pub struct CompiledCircuit {
    gate_constraint: GateConstraints,
    copy_constraint: CopyConstraints,
    srs: Srs,
    domain: GeneralEvaluationDomain<Fr>,
    pub size: usize
}

impl CompiledCircuit {
    pub fn new (gate_constraint: GateConstraints,copy_constraint: CopyConstraints,
    srs: Srs, domain: GeneralEvaluationDomain<Fr>, size: usize) -> Self{
        Self {
            gate_constraint,
            copy_constraint,
            srs,
            domain,
            size
        }
    }


}
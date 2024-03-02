use ark_ec::PairingEngine;
use ark_poly::{univariate::DensePolynomial, GeneralEvaluationDomain};
use ark_bls12_381::Fr;
use constrain::{CopyConstrains, GateConstrains};
use srs::Srs;
use crate::constrain::{CopyConstraints, GateConstraints};

pub type G1Point = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Affine;
pub type G2Point = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Affine;
pub type Polynomial = DensePolynomial<Fr>;

mod circuit;
mod errors;
mod gate;
mod srs;
mod variable;
mod constrain;

pub struct CompiledCircuit {
    gate_constraint: GateConstraints,
    copy_constraint: CopyConstraints,
    srs: Srs,
    domain: GeneralEvaluationDomain<Fr>,
    pub size: usize
}

impl CompiledCircuit {
    pub fn new (gate_constrains: GateConstraints,copy_constrains: CopyConstraints,
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
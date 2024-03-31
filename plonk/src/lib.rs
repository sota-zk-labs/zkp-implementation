use ark_bls12_381::Fr;
use ark_ec::PairingEngine;
use ark_poly::{univariate::DensePolynomial};

use kzg::srs::Srs;

use crate::constrain::{CopyConstraints, GateConstraints};

pub type G1Point = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Affine;
pub type G2Point = <ark_bls12_381::Bls12_381 as PairingEngine>::G2Affine;
pub type Polynomial = DensePolynomial<Fr>;


pub mod circuit;
mod gate;
mod constrain;
pub mod prover;
mod challenge;
mod slice_polynomial;
pub mod verifier;
#[derive(Debug)]
pub struct CompiledCircuit {
    gate_constraint: GateConstraints,
    copy_constraint: CopyConstraints,
    srs: Srs,
    pub size: usize,
}

impl CompiledCircuit {
    pub fn new (gate_constraint: GateConstraints,copy_constraint: CopyConstraints,
    srs: Srs, size: usize) -> Self{
        Self {
            gate_constraint,
            copy_constraint,
            srs,
            size
        }
    }

    pub fn gate_constraint(&self) -> &GateConstraints {
        &self.gate_constraint
    }
    pub fn copy_constraint(&self) -> &CopyConstraints {
        &self.copy_constraint
    }
    pub fn srs(&self) -> &Srs {
        &self.srs
    }
}
use kzg::srs::Srs;

use crate::constrain::{CopyConstraints, GateConstraints};

#[derive(Debug)]
pub struct CompiledCircuit {
    pub size: usize,

    gate_constraint: GateConstraints,
    copy_constraint: CopyConstraints,
    srs: Srs,
}

impl CompiledCircuit {
    pub fn new(gate_constraint: GateConstraints, copy_constraint: CopyConstraints,
               srs: Srs, size: usize) -> Self {
        Self {
            gate_constraint,
            copy_constraint,
            srs,
            size,
        }
    }

    pub fn gate_constraints(&self) -> &GateConstraints {
        &self.gate_constraint
    }
    pub fn copy_constraints(&self) -> &CopyConstraints {
        &self.copy_constraint
    }
    pub fn srs(&self) -> Srs {
        self.srs.clone()
    }
}
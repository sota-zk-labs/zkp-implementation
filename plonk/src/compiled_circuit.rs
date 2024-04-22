use kzg::srs::Srs;

use crate::constraint::{CopyConstraints, GateConstraints};

/// Represents a compiled circuit with gate and copy constraints, along with the structured reference string (SRS).
#[derive(Debug, PartialEq)]
pub struct CompiledCircuit {
    /// The size of the compiled circuit.
    pub size: usize,

    gate_constraint: GateConstraints,
    copy_constraint: CopyConstraints,
    srs: Srs,
}

impl CompiledCircuit {
    /// Creates a new `CompiledCircuit` instance.
    ///
    /// # Parameters
    ///
    /// - `gate_constraint`: The gate constraints of the compiled circuit.
    /// - `copy_constraint`: The copy constraints of the compiled circuit.
    /// - `srs`: The structured reference string (SRS) associated with the compiled circuit.
    /// - `size`: The size of the compiled circuit.
    pub fn new(
        gate_constraint: GateConstraints,
        copy_constraint: CopyConstraints,
        srs: Srs,
        size: usize,
    ) -> Self {
        Self {
            gate_constraint,
            copy_constraint,
            srs,
            size,
        }
    }

    /// Returns a reference to the gate constraints of the compiled circuit.
    pub fn gate_constraints(&self) -> &GateConstraints {
        &self.gate_constraint
    }

    /// Returns a reference to the copy constraints of the compiled circuit.
    pub fn copy_constraints(&self) -> &CopyConstraints {
        &self.copy_constraint
    }

    /// Returns a clone of the structured reference string (SRS) associated with the compiled circuit.
    pub fn srs(&self) -> Srs {
        self.srs.clone()
    }
}

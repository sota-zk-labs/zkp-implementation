use crate::constraint::{CopyConstraints, GateConstraints};

/// Represents a compiled circuit with gate and copy constraints.
#[derive(Debug)]
pub struct CompiledCircuit {
    /// The size of the compiled circuit.
    pub size: usize,

    gate_constraint: GateConstraints,
    copy_constraint: CopyConstraints,
}

impl CompiledCircuit {
    /// Creates a new `CompiledCircuit` instance.
    ///
    /// # Parameters
    ///
    /// - `gate_constraint`: The gate constraints of the compiled circuit.
    /// - `copy_constraint`: The copy constraints of the compiled circuit.
    /// - `size`: The size of the compiled circuit.
    pub fn new(
        gate_constraint: GateConstraints,
        copy_constraint: CopyConstraints,
        size: usize,
    ) -> Self {
        Self {
            gate_constraint,
            copy_constraint,
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
}

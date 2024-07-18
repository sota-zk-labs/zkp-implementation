use ark_bls12_381::Fr;
use ark_ff::{One, Zero};

/// Enum representing the position of a wire in a gate.
#[derive(Clone, PartialEq, Debug)]
pub enum Position {
    /// Dummy position indicating no wire connection.
    Dummy,
    /// Position indicating a wire connection with indices (layer, index).
    Pos(usize, usize),
}

#[derive(Clone, PartialEq, Debug)]
/// Struct representing a gate in the circuit.
pub struct Gate {
    /// Position of the input wire A.
    a_pos: Position,
    /// Position of the input wire B.
    b_pos: Position,
    /// Position of the output wire C.
    c_pos: Position,
    /// Q_L coefficient.
    pub(crate) q_l: Fr,
    /// Q_R coefficient.
    pub(crate) q_r: Fr,
    /// Q_O coefficient.
    pub(crate) q_o: Fr,
    /// Q_M coefficient.
    pub(crate) q_m: Fr,
    /// Q_C coefficient.
    pub(crate) q_c: Fr,
    /// Pi coefficient.
    pub(crate) pi: Fr,
}

impl Gate {
    /// Creates a new addition gate.
    pub(crate) fn new_add_gate(
        a_pos: Position,
        b_pos: Position,
        c_pos: Position,
        pi: Option<Fr>,
    ) -> Self {
        Self {
            a_pos,
            b_pos,
            c_pos,
            q_l: Fr::one(),
            q_r: Fr::one(),
            q_m: Fr::zero(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
            pi: -pi.unwrap_or(Fr::zero()),
        }
    }

    /// Creates a new multiplication gate.
    pub(crate) fn new_mul_gate(
        a_pos: Position,
        b_pos: Position,
        c_pos: Position,
        pi: Option<Fr>,
    ) -> Self {
        Self {
            a_pos,
            b_pos,
            c_pos,
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_m: Fr::one(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
            pi: -pi.unwrap_or(Fr::zero()),
        }
    }

    /// Creates a new constant gate.
    pub(crate) fn new_constant_gate(
        a_pos: Position,
        b_pos: Position,
        c_pos: Position,
        constant: Fr,
        pi: Option<Fr>,
    ) -> Self {
        Self {
            a_pos,
            b_pos,
            c_pos,
            q_l: Fr::one(),
            q_r: Fr::zero(),
            q_m: Fr::zero(),
            q_o: Fr::zero(),
            q_c: -constant,
            pi: -pi.unwrap_or(Fr::zero()),
        }
    }

    /// Creates a new dummy gate.
    pub(crate) fn new_dummy_gate() -> Self {
        Self {
            a_pos: Position::Dummy,
            b_pos: Position::Dummy,
            c_pos: Position::Dummy,
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_m: Fr::zero(),
            q_o: Fr::zero(),
            q_c: Fr::zero(),
            pi: Fr::zero(),
        }
    }

    /// Checks if the gate is a dummy gate.
    pub(crate) fn is_dummy_gate(&self) -> bool {
        self.a_pos == Position::Dummy
    }

    /// Gets the position of wire A.
    pub(crate) fn get_a_wire(&self) -> &Position {
        &self.a_pos
    }

    /// Gets the position of wire B.
    pub(crate) fn get_b_wire(&self) -> &Position {
        &self.b_pos
    }

    /// Gets the position of wire C.
    pub(crate) fn get_c_wire(&self) -> &Position {
        &self.c_pos
    }
}

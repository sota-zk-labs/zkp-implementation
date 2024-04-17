use ark_bls12_381::Fr;
use ark_ff::{One, Zero};

#[derive(PartialEq)]
pub enum Position {
    Dummy,
    Pos(usize, usize),
}

pub struct Gate {
    a_pos: Position,
    b_pos: Position,
    c_pos: Position,
    pub(crate) q_l: Fr,
    pub(crate) q_r: Fr,
    pub(crate) q_o: Fr,
    pub(crate) q_m: Fr,
    pub(crate) q_c: Fr,
    pub(crate) pi: Fr,
}

impl Gate {
    //create an add gate
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

    pub(crate) fn new_mult_gate(
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
            q_c: -Fr::from(constant),
            pi: -pi.unwrap_or(Fr::zero()),
        }
    }

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
    pub(crate) fn is_dummy_gate(&self) -> bool {
        self.a_pos == Position::Dummy
    }
    pub(crate) fn get_a_wire(&self) -> &Position {
        &self.a_pos
    }

    pub(crate) fn get_b_wire(&self) -> &Position {
        &self.b_pos
    }

    pub(crate) fn get_c_wire(&self) -> &Position {
        &self.c_pos
    }
}

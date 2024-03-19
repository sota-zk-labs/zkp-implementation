use ark_bls12_381::Fr;
use ark_ff::{One, Zero};

#[allow(dead_code)]
#[derive(PartialEq)]
pub enum Position{
    Dummy,
    Pos(usize, usize)
}
#[allow(dead_code)]
pub struct Gate {
    a_wire: Position,
    b_wire: Position,
    c_wire: Position,
    pub(crate) q_l: Fr,
    pub(crate) q_r: Fr,
    pub(crate) q_o: Fr,
    pub(crate) q_m: Fr,
    pub(crate) q_c: Fr,
    pub(crate) pi: Fr,
}

#[allow(dead_code)]
impl Gate {

    pub fn new() -> Gate {
        Self {
            a_wire: Position::Dummy,
            b_wire: Position::Dummy,
            c_wire: Position::Dummy,
            q_l: Fr::from(0),
            q_r: Fr::from(0),
            q_o: Fr::from(0),
            q_m: Fr::from(0),
            q_c: Fr::from(0),
            pi: Fr::from(0),
        }
    }
    fn unwrap_option_value(x: Option<Fr>) -> Fr {
        let negative_one = -Fr::one();

        let new_val = if let Some(x) = x {
            let res = negative_one * x;
            res
        } else {
            Fr::zero()
        };

        new_val
    }

    //create an add gate
    pub(crate) fn new_add_gate(
        a_id: Position,
        b_id: Position,
        c_id: Position,
        pi: Option<Fr>,
    ) -> Self {
        let new_pi = Self::unwrap_option_value(pi);

        Self {
            a_wire: a_id,
            b_wire: b_id,
            c_wire: c_id,
            q_l: Fr::one(),
            q_r: Fr::one(),
            q_m: Fr::zero(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
            pi: new_pi,
        }
    }


    pub(crate) fn new_mult_gate(
        a_id: Position,
        b_id: Position,
        c_id: Position,
        pi: Option<Fr>,
    ) -> Self {
        let new_pi = Self::unwrap_option_value(pi);

        Self {
            a_wire: a_id,
            b_wire: b_id,
            c_wire: c_id,
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_m: Fr::one(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
            pi: new_pi,
        }
    }

    pub(crate) fn new_constant_gate(
        a_id: Position,
        b_id: Position,
        c_id: Position,
        constant: Fr,
        pi: Option<Fr>,
    ) -> Self {
        let new_pi = Self::unwrap_option_value(pi);

        Self {
            a_wire: a_id,
            b_wire: b_id,
            c_wire: c_id,
            q_l: Fr::one(),
            q_r: Fr::zero(),
            q_m: Fr::zero(),
            q_o: Fr::zero(),
            q_c: -Fr::from(constant),
            pi: new_pi,
        }
    }

    pub(crate) fn new_dummy_gate() -> Self {
        Self {
            a_wire: Position::Dummy,
            b_wire: Position::Dummy,
            c_wire: Position::Dummy,
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_m: Fr::zero(),
            q_o: Fr::zero(),
            q_c: Fr::zero(),
            pi: Fr::zero(),
        }
    }


    pub(crate) fn get_a_wire(&self) -> &Position {
        &self.a_wire
    }

    pub(crate) fn get_b_wire(&self) -> &Position {
        &self.b_wire
    }

    pub(crate) fn get_c_wire(&self) -> &Position {
        &self.c_wire
    }
}
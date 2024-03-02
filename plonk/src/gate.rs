use ark_bls12_381::Fr;
use ark_ff::{One, Zero};

pub struct Gate {
    a_wire: (usize, usize),
    b_wire: (usize, usize),
    c_wire: (usize, usize),
    pub(crate) q_l: Fr,
    pub(crate) q_r: Fr,
    pub(crate) q_o: Fr,
    pub(crate) q_m: Fr,
    pub(crate) q_c: Fr,
    pub(crate) pi: Fr,
}

impl Gate {

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
        a_id: (usize, usize), 
        b_id: (usize, usize), 
        c_id: (usize, usize), 
        pi: Option<Fr>
    ) -> Self {
        let new_pi = Self::unwrap_option_value(pi);
        
        Self {
            a_wire: a_id,
            b_wire: b_id, 
            c_wire: c_id,
            q_l: -Fr::one(),
            q_r: Fr::one(), 
            q_m: Fr::zero(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
            pi: new_pi
        }
    }

    
    pub(crate) fn new_mult_gate(
        a_id: (usize, usize), 
        b_id: (usize, usize), 
        c_id: (usize, usize), 
        pi: Option<Fr>
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
            pi: new_pi
        }
    }


    pub(crate) fn new_add_constant_gate(
        a_id: (usize, usize), 
        b_id: (usize, usize), 
        c_id: (usize, usize),  
        constant: Option<Fr>,
        pi: Option<Fr>
    ) -> Self {
        let new_pi = Self::unwrap_option_value(pi);
        let new_constant = Self::unwrap_option_value(constant);
        Self {
            a_wire: a_id,
            b_wire: b_id, 
            c_wire: c_id,
            q_l: -Fr::one(),
            q_r: Fr::one(), 
            q_m: Fr::zero(),
            q_o: -Fr::one(),
            q_c: new_constant,
            pi: new_pi
        }
    }
    
    pub(crate) fn new_mult_constant_gate(
        a_id: (usize, usize), 
        b_id: (usize, usize), 
        c_id: (usize, usize),  
        constant: Option<Fr>,
        pi: Option<Fr>
    ) -> Self {
        let new_pi = Self::unwrap_option_value(pi);
        let new_constant = Self::unwrap_option_value(constant);
        Self {
            a_wire: a_id,
            b_wire: b_id, 
            c_wire: c_id,
            q_l: Fr::zero(),
            q_r: Fr::zero(), 
            q_m: Fr::one(),
            q_o: -Fr::one(),
            q_c: new_constant,
            pi: new_pi
        }
    }

    pub(crate) fn get_a_wire(&self) -> (usize, usize) {
        self.a_wire
    }

    pub(crate) fn get_b_wire(&self) -> (usize, usize) {
        self.b_wire
    }

    pub(crate) fn get_c_wire(&self) -> (usize, usize) {
        self.c_wire
    }



}
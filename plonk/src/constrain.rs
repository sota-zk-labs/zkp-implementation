use crate::Polynomial;

pub struct GateConstrains {
    f_ax: Polynomial,
    f_bx: Polynomial,
    f_cx: Polynomial,
    q_lx: Polynomial,
    q_rx: Polynomial,
    q_ox: Polynomial,
    q_mx: Polynomial,
    q_cx: Polynomial,
    pi_x: Polynomial
}

impl GateConstrains {
    pub fn new(f_ax: Polynomial, f_bx: Polynomial, f_cx: Polynomial,
        q_lx: Polynomial, q_rx: Polynomial, q_ox: Polynomial,
        q_mx: Polynomial, q_cx: Polynomial, pi_x: Polynomial) -> Self {
        
        Self {
            f_ax,
            f_bx,
            f_cx,
            q_lx,
            q_rx,
            q_ox,
            q_mx,
            q_cx,
            pi_x
        }

    }
}

pub struct CopyConstrains {
    
}
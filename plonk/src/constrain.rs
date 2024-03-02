use crate::Polynomial;

pub struct GateConstraints {
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

impl GateConstraints {
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

pub struct CopyConstraints {
    s_sigma_1: Polynomial,
    s_sigma_2: Polynomial,
    s_sigma_3: Polynomial,
}

impl CopyConstraints {
    pub fn new(s_sigma_1: Polynomial, s_sigma_2: Polynomial, s_sigma_3: Polynomial) -> Self{
        Self {
            s_sigma_1,
            s_sigma_2,
            s_sigma_3
        }
    }
}
use ark_bls12_381::Fr;
use crate::Polynomial;
#[derive(Debug)]
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

    pub fn get_f_ax(&self) -> &Polynomial {
        &self.f_ax
    }

    pub fn get_f_bx(&self) -> &Polynomial {
        &self.f_bx
    }

    pub fn get_f_cx(&self) -> &Polynomial {
        &self.f_cx
    }

    pub fn get_q_lx(&self) -> &Polynomial { &self.q_lx}

    pub fn get_q_rx(&self) -> &Polynomial { &self.q_rx}
    pub fn get_q_ox(&self) -> &Polynomial { &self.q_ox}
    pub fn get_q_mx(&self) -> &Polynomial { &self.q_mx}
    pub fn get_q_cx(&self) -> &Polynomial { &self.q_cx}
    pub fn get_pi_x(&self) -> &Polynomial { &self.pi_x}





}
#[derive(Debug)]
pub struct CopyConstraints {
    s_sigma_1: Polynomial,
    s_sigma_2: Polynomial,
    s_sigma_3: Polynomial,
    k1: Fr,
    k2: Fr
}

impl CopyConstraints {
    pub fn new(s_sigma_1: Polynomial, s_sigma_2: Polynomial, s_sigma_3: Polynomial, k1: Fr, k2: Fr) -> Self{
        Self {
            s_sigma_1,
            s_sigma_2,
            s_sigma_3,
            k1,
            k2
        }
    }


    pub fn get_ssigma_1(&self) -> &Polynomial {
        &self.s_sigma_1
    }

    pub fn get_ssigma_2(&self) -> &Polynomial {
        &self.s_sigma_2
    }

    pub fn get_ssigma_3(&self) -> &Polynomial {
        &self.s_sigma_3
    }

    pub fn get_k1(&self) -> &Fr {
        &self.k1
    }

    pub fn get_k2(&self) -> &Fr {
        &self.k2
    }



}
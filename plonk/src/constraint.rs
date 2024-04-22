use crate::types::Polynomial;
use ark_bls12_381::Fr;

/// Represents gate constraints for a compiled circuit.
#[derive(Debug, PartialEq)]
pub struct GateConstraints {
    /// Polynomial representing the constraint function for the A wire.
    f_ax: Polynomial,
    /// Polynomial representing the constraint function for the B wire.
    f_bx: Polynomial,
    /// Polynomial representing the constraint function for the C wire.
    f_cx: Polynomial,
    /// Polynomial representing the constraint function for the Q_L.
    q_lx: Polynomial,
    /// Polynomial representing the constraint function for the Q_R.
    q_rx: Polynomial,
    /// Polynomial representing the constraint function for the Q_O.
    q_ox: Polynomial,
    /// Polynomial representing the constraint function for the Q_M.
    q_mx: Polynomial,
    /// Polynomial representing the constraint function for the Q_C.
    q_cx: Polynomial,
    /// Polynomial representing the constraint function for the Public input Pi.
    pi_x: Polynomial,
}

impl GateConstraints {
    /// Creates a new instance of `GateConstraints`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        f_ax: Polynomial,
        f_bx: Polynomial,
        f_cx: Polynomial,
        q_lx: Polynomial,
        q_rx: Polynomial,
        q_ox: Polynomial,
        q_mx: Polynomial,
        q_cx: Polynomial,
        pi_x: Polynomial,
    ) -> Self {
        Self {
            f_ax,
            f_bx,
            f_cx,
            q_lx,
            q_rx,
            q_ox,
            q_mx,
            q_cx,
            pi_x,
        }
    }

    pub fn f_ax(&self) -> &Polynomial {
        &self.f_ax
    }
    pub fn f_bx(&self) -> &Polynomial {
        &self.f_bx
    }
    pub fn f_cx(&self) -> &Polynomial {
        &self.f_cx
    }
    pub fn q_lx(&self) -> &Polynomial {
        &self.q_lx
    }
    pub fn q_rx(&self) -> &Polynomial {
        &self.q_rx
    }
    pub fn q_ox(&self) -> &Polynomial {
        &self.q_ox
    }
    pub fn q_mx(&self) -> &Polynomial {
        &self.q_mx
    }
    pub fn q_cx(&self) -> &Polynomial {
        &self.q_cx
    }
    pub fn pi_x(&self) -> &Polynomial {
        &self.pi_x
    }
}

/// Represents copy constraints for a compiled circuit.
#[derive(Debug, PartialEq)]
pub struct CopyConstraints {
    /// Polynomial representing the first prescribe function (sigma_1).
    s_sigma_1: Polynomial,
    /// Polynomial representing the second prescribe function (sigma_2).
    s_sigma_2: Polynomial,
    /// Polynomial representing the third prescribe function (sigma_3).
    s_sigma_3: Polynomial,
    /// First constant factor used in copy constraint calculations.
    k1: Fr,
    /// Second constant factor used in copy constraint calculations.
    k2: Fr,
}

impl CopyConstraints {
    /// Creates a new instance of `CopyConstraints`.
    pub fn new(
        s_sigma_1: Polynomial,
        s_sigma_2: Polynomial,
        s_sigma_3: Polynomial,
        k1: Fr,
        k2: Fr,
    ) -> Self {
        Self {
            s_sigma_1,
            s_sigma_2,
            s_sigma_3,
            k1,
            k2,
        }
    }

    pub fn get_s_sigma_1(&self) -> &Polynomial {
        &self.s_sigma_1
    }

    pub fn get_s_sigma_2(&self) -> &Polynomial {
        &self.s_sigma_2
    }

    pub fn get_s_sigma_3(&self) -> &Polynomial {
        &self.s_sigma_3
    }

    pub fn k1(&self) -> &Fr {
        &self.k1
    }

    pub fn k2(&self) -> &Fr {
        &self.k2
    }
}

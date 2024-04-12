use std::ops::Add;

use ark_bls12_381::Fr;

use crate::types::G1Point;

/// Opening at (point, evaluation)
#[derive(Debug, Clone)]
pub struct KzgOpening(pub G1Point, pub Fr);

impl KzgOpening {
    pub fn eval(self) -> Fr {
        self.1
    }
}

impl Add for KzgOpening {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let eval = self.1 + rhs.1;
        let witness = self.0 + self.0;
        Self(witness.into(), eval)
    }
}

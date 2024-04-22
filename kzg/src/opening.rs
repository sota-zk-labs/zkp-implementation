use std::ops::Add;

use ark_bls12_381::Fr;

use crate::types::G1Point;

/// Represents an opening at a point with its corresponding evaluation.
///
/// `KzgOpening` encapsulates a `G1Point` representing the point and an `Fr` representing the evaluation.
#[derive(Debug, Clone)]
pub struct KzgOpening(pub G1Point, pub Fr);

impl KzgOpening {
    /// Retrieves the evaluation associated with the opening.
    ///
    /// # Returns
    ///
    /// The evaluation (`Fr`) of the opening.
    pub fn eval(self) -> Fr {
        self.1
    }
}

impl Add for KzgOpening {
    type Output = Self;

    /// Combines two openings by adding their evaluations and doubling the witness point.
    ///
    /// # Parameters
    ///
    /// - `self`: The first `KzgOpening` instance.
    /// - `rhs`: The second `KzgOpening` instance to be added.
    ///
    /// # Returns
    ///
    /// A new `KzgOpening` instance representing the combined opening.
    fn add(self, rhs: Self) -> Self::Output {
        // Add evaluations
        let eval = self.1 + rhs.1;
        // Double the witness point
        let witness = self.0 + self.0;
        Self(witness.into(), eval)
    }
}

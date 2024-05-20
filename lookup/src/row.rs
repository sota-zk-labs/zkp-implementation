use std::ops::{Add, AddAssign, Mul};

use ark_ff::PrimeField;

/// This struct represents a row in a table.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct Row<F: PrimeField>(pub Vec<F>);

impl<F: PrimeField> Add<Self> for Row<F> {
    type Output = Self;

    /// Adds two rows element-wise.
    fn add(self, rhs: Self) -> Self::Output {
        assert_eq!(self.0.len(), rhs.0.len());
        Self(rhs.0.iter().zip(self.0).map(|(x, y)| *x + y).collect())
    }
}

impl<F: PrimeField> AddAssign<Self> for Row<F> {
    fn add_assign(&mut self, rhs: Self) {
        assert_eq!(self.0.len(), rhs.0.len());
        for i in 0..self.0.len() {
            self.0[i] += rhs.0[i];
        }
    }
}

impl<F: PrimeField> Mul<F> for Row<F> {
    type Output = Row<F>;

    /// Multiplies each element of the row by a scalar.
    fn mul(self, rhs: F) -> Self::Output {
        Row(self.0.iter().map(|x| *x * rhs).collect())
    }
}

/// Converts a slice of 128-bit unsigned integers to a `Row` of field elements.
///
/// # Arguments
///
/// * `v`: A slice of `u128` values to be converted to field elements.
///
/// returns: A `Row<F>` containing the field elements corresponding to the input integers.
pub fn ints_to_fields<F: PrimeField>(v: &[u128]) -> Row<F> {
    Row(v.iter().map(|e| F::from(*e)).collect())
}

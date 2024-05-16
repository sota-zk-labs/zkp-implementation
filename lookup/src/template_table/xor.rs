use ark_ff::PrimeField;

use crate::multiset::Multiset;

/// This struct represents a table generated from XOR operations.
///
/// Each element has the form (a, b, a xor b).
pub struct XorTable<F: PrimeField> {
    table: Vec<Multiset<F>>,
}

impl<F: PrimeField> XorTable<F> {
    /// Creates a new instance of the XOR table with a specified size.
    ///
    /// # Arguments
    ///
    /// * `n`: The size of the XOR table. Must be less than or equal to 10.
    ///
    /// returns: a new instance of the XOR table.
    ///
    /// # Panics
    ///
    /// Panics if `n` is greater than 10.
    pub fn new(n: usize) -> Self {
        let mut table = vec![];
        assert!(n <= 10);
        for i in 0..(1 << (n - 1)) as u128 {
            for j in 0..(1 << (n - 1)) as u128 {
                table.push(Multiset(vec![F::from(i), F::from(j), F::from(i ^ j)]));
            }
        }
        Self { table }
    }

    /// Returns a reference to the XOR table.
    pub fn table(&self) -> &Vec<Multiset<F>> {
        &self.table
    }
}

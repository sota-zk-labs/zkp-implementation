use ark_ff::PrimeField;

use crate::row::Row;

/// This struct represents a table generated from XOR operations.
///
/// Each element has the form (a, b, a xor b).
pub struct XorTable<F: PrimeField> {
    table: Vec<Row<F>>,
}

impl<F: PrimeField> XorTable<F> {
    /// Creates a new instance of the XOR table with a specified size.
    ///
    /// # Arguments
    ///
    /// * `n`: The size of the XOR table.
    ///
    /// returns: a new instance of the XOR table.
    pub fn new(n: usize) -> Self {
        let mut table = vec![];
        for i in 0..(1 << (n - 1)) as u128 {
            for j in 0..(1 << (n - 1)) as u128 {
                table.push(Row(vec![F::from(i), F::from(j), F::from(i ^ j)]));
            }
        }
        Self { table }
    }

    /// Returns a reference to the XOR table.
    pub fn table(&self) -> &Vec<Row<F>> {
        &self.table
    }
}

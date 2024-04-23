use ark_ff::PrimeField;

pub struct Multiset<F: PrimeField>(Vec<F>);

impl<F: PrimeField> Multiset<F> {

    pub fn get_ref(&self) -> &Vec<F> {
        &self.0
    }
    /// Creates an empty Multiset
    pub fn new() -> Self {
        Multiset(vec![])
    }

    /// Pushes a value into the end of the set
    pub fn push(&mut self, val: F) {
        self.0.push(val);
    }

    /// Pushes `n` identical values into the set
    pub fn extend(&mut self, n: usize, val: F) {
        let elements = vec![val; n];
        self.0.extend(elements);
    }

    /// Fetches last element in multiset
    ///
    /// Panics if there are no elements
    pub fn last(&self) -> F {
        *self.0.last().unwrap()
    }


}
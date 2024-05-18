use std::ops::{Add, Mul};

use ark_ff::PrimeField;

use crate::errors::Error;
use crate::pcs::base_pcs::BasePCS;
use crate::types::Poly;

/// This trait represents the additive homomorphic PCS, i.e.
/// - `com(a + b) = com(a) + com(b)`
/// - `z * com(a) = com(za)`
pub trait AdditiveHomomorphicPCS<F: PrimeField>: BasePCS<F>
    where Self::Commitment: Add<Output=Self::Commitment> + Mul<F, Output=Self::Commitment>, {
    /// Aggregates a list of elements using a random challenge.
    ///
    /// Let `z` be the challenge, and the elements be `e0, e2, ..., en`. The aggregate result is
    /// `e0 + e1*z + e2*z^2 + ... + en*z^n`.
    ///
    /// # Arguments
    ///
    /// * `elements`: The vector of the elements to be aggregated.
    /// * `challenge`: The challenge used for aggregation.
    ///
    /// returns: `Ok(E)` if the aggregation is successful, otherwise returns an `Error`.
    #[allow(clippy::ptr_arg)]
    #[allow(clippy::needless_range_loop)]
    fn aggregate<E>(elements: &Vec<&E>, challenge: &F) -> Result<E, Error>
        where
            E: Add<E, Output=E>,
            E: Mul<F, Output=E>,
            E: Clone,
    {
        if elements.is_empty() {
            return Err(Error::EmptyVec);
        }
        let mut res = elements[0].clone();
        let mut pow = *challenge;
        for i in 1..elements.len() {
            res = res + (elements[i].clone() * pow);
            pow *= challenge;
        }
        Ok(res)
    }
    /// This function treats like `aggregate` function, but separated because
    /// `DensePolynomial + DensePolynomial` does not work (which also means it does not
    /// satisfy `E: Add<E, Output = E>`).
    ///
    /// # Arguments
    ///
    /// * `elements`:The vector of the polynomials to be aggregated.
    /// * `challenge`: The challenge used for aggregation.
    ///
    /// returns: `Ok(DensePolynomial<F>)` if the aggregation is successful, otherwise returns an `Error`.
    #[allow(clippy::ptr_arg)]
    #[allow(clippy::needless_range_loop)]
    fn aggregate_polys(elements: &Vec<&Poly<F>>, challenge: &F) -> Result<Poly<F>, Error> {
        if elements.is_empty() {
            return Err(Error::EmptyVec);
        }
        let mut res = elements[0].clone();
        let mut pow = *challenge;
        for i in 1..elements.len() {
            res = res + (elements[i] * pow);
            pow *= challenge;
        }
        Ok(res)
    }
}

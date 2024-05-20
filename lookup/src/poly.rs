use std::ops::SubAssign;

use ark_ff::{PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial};
use ark_std::cfg_iter_mut;

use crate::errors::Error;
use crate::types::{Domain, Poly};

/// Provides some extra methods for `DensePolynomial`
pub trait ExtraDensePoly<F: PrimeField> {
    fn from_evaluations(v: &[F], domain: &Domain<F>) -> Self;
    fn lagrange_basis(n: usize, domain: &Domain<F>) -> Self;
    fn mul_poly_over_domain_in_place(
        &mut self,
        other: &Self,
        domain: &Domain<F>,
    ) -> Result<(), Error>;
    fn mul_over_domain(&self, other: &Self, domain: &Domain<F>) -> Self;
    fn mul_scalar_in_place(&mut self, scalar: &F);
    fn from_constant(c: &F) -> Self;
    fn quotient_poly(&self, z: &F) -> Self;
}

impl<F: PrimeField> ExtraDensePoly<F> for DensePolynomial<F> {
    /// Converts a vector of field elements into a polynomial over the specified domain.
    ///
    /// # Arguments
    ///
    /// * `evaluations`: A slice of field elements representing the coefficients of the polynomial.
    /// * `domain`: The domain over which the polynomial is defined.
    ///
    /// returns: A `DensePolynomial<F>` representing the polynomial over the specified domain.
    fn from_evaluations(evaluations: &[F], domain: &Domain<F>) -> Self {
        Poly::from_coefficients_vec(domain.ifft(evaluations))
    }

    /// Computes the nth Lagrange basis polynomial over the given domain.
    ///
    /// # Arguments
    ///
    /// * `n`: The index of the Lagrange basis polynomial to compute.
    /// * `domain`: The domain over which the Lagrange basis polynomials are defined.
    ///
    /// returns: A `DensePolynomial<F>` representing the nth Lagrange basis polynomial over the specified domain.
    fn lagrange_basis(n: usize, domain: &Domain<F>) -> Self {
        assert!(n < domain.size());
        let mut evaluations = vec![F::zero(); domain.size()];
        evaluations[n] = F::one();
        Self::from_evaluations(&evaluations, domain)
    }

    /// Multiplies the polynomial by another polynomial over the given domain in place.
    ///
    /// # Arguments
    ///
    /// * `other`: Another polynomial to multiply with.
    /// * `domain`: The domain over which the polynomials are defined.
    ///
    /// # Errors
    ///
    /// Returns an error if the sum of the lengths of coefficients of both polynomials is larger than the size of the domain.
    fn mul_poly_over_domain_in_place(
        &mut self,
        other: &Self,
        domain: &Domain<F>,
    ) -> Result<(), Error> {
        if self.coeffs().len() + other.coeffs().len() > domain.size() {
            return Err(Error::PolyNotFitInDomain(
                "The number of coefficients of two polynomials cannot be larger than domain's size"
                    .to_string(),
            ));
        }
        let mut self_evaluations = self.evaluate_over_domain_by_ref(*domain);
        let other_evaluations = other.evaluate_over_domain_by_ref(*domain);
        self_evaluations *= &other_evaluations;
        *self = self_evaluations.interpolate();
        Ok(())
    }

    /// Multiply by another polynomial over a given domain
    ///
    /// # Arguments
    ///
    /// * `other`: Another polynomial to multiply with.
    /// * `domain`: The domain over which the polynomials are defined.
    ///
    /// returns: The product of two polynomials
    fn mul_over_domain(&self, other: &Self, domain: &Domain<F>) -> Self {
        let mut res = self.clone();
        res.mul_poly_over_domain_in_place(other, domain).unwrap();
        res
    }

    /// Multiplies the polynomial by a scalar in place.
    ///
    /// # Arguments
    ///
    /// * `scalar`: The scalar value to multiply the polynomial by.
    fn mul_scalar_in_place(&mut self, scalar: &F) {
        if self.is_zero() || scalar.is_zero() {
            *self = Self::zero();
        } else {
            cfg_iter_mut!(self).for_each(|e| {
                *e *= scalar;
            });
        }
    }

    /// Constructs a polynomial from a constant value.
    ///
    /// # Arguments
    ///
    /// * `c`: The constant value.
    ///
    /// returns: A new polynomial with the constant value as its only coefficient.
    fn from_constant(c: &F) -> Self {
        Self::from_coefficients_vec(vec![*c])
    }

    /// Computes `(f(x) - f(z)) / (x - z)`
    ///
    /// # Arguments
    ///
    /// * `z`: The value at which the polynomial is evaluated.
    ///
    /// returns: The quotient polynomial
    fn quotient_poly(&self, z: &F) -> Self {
        let fz = self.evaluate(z);
        let divisor = Self::from_coefficients_vec(vec![z.neg(), F::one()]);
        let mut res = self.clone();
        res.sub_assign(&Poly::from_constant(&fz));
        &res / &divisor
    }
}

//

#[cfg(test)]
mod test {
    use ark_poly::{DenseUVPolynomial, EvaluationDomain};

    use crate::pcs::kzg10::KzgField;
    use crate::poly::ExtraDensePoly;
    use crate::row::ints_to_fields;
    use crate::types::{Domain, Poly};

    #[test]
    /// Tests the correctness of `mul_over_domain` function.
    ///
    /// This test validates the correctness of multiplying two polynomials over a given domain
    fn mul_over_domain() {
        // x^2 + 2x + 1
        let f1 = Poly::<KzgField>::from_coefficients_vec(ints_to_fields(&[1, 2, 1]).0);
        // x^3 + 3x + 2
        let f2 = Poly::<KzgField>::from_coefficients_vec(ints_to_fields(&[2, 3, 0, 1]).0);
        let domain = Domain::<KzgField>::new(10).unwrap();
        let f3 = f1.mul_over_domain(&f2, &domain);
        assert_eq!(f3, &f1 * &f2);
    }
}

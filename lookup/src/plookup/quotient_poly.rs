use std::marker::PhantomData;

use ark_ff::{PrimeField, Zero};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};

use crate::plookup::types::PlookupEvaluations;
use crate::poly::ExtraDensePoly;
use crate::types::{Domain, Poly};

pub struct QuotientPoly<F>(PhantomData<F>);

#[allow(clippy::too_many_arguments)]
impl<F: PrimeField> QuotientPoly<F> {
    /// Computes quotient polynomial in `Plookup`.
    ///
    /// # Arguments
    ///
    /// * `f`
    /// * `t`
    /// * `h1`
    /// * `h2`
    /// * `z`
    /// * `domain`
    /// * `beta`
    /// * `gamma`
    ///
    /// returns: The quotient polynomial.
    pub fn compute_quotient_poly(
        f: &Poly<F>,
        t: &Poly<F>,
        h1: &Poly<F>,
        h2: &Poly<F>,
        z: &Poly<F>,
        domain: &Domain<F>,
        beta: F,
        gamma: F,
    ) -> Poly<F> {
        let domain_2n = &Domain::<F>::new(2 * domain.size()).unwrap();
        let check_z1_zn = Self::check_z1_zn_equal_one(z, domain, domain_2n);
        let check_z = Self::check_z_poly(f, t, h1, h2, z, gamma, beta, domain, domain_2n);
        let check_h1_h2 = Self::check_last_h1_equal_first_h2(h1, h2, domain, domain_2n);

        let aggregate = check_z1_zn + check_z + check_h1_h2;
        let (q, r) = aggregate.divide_by_vanishing_poly(*domain).unwrap();
        assert!(r.is_zero());
        q
    }

    /// Evaluates quotient polynomial at `evaluation_challenge`.
    ///
    /// # Arguments
    ///
    /// * `evaluations`: The computed evaluations.
    /// * `beta`
    /// * `gamma`
    /// * `evaluation_challenge`
    /// * `domain`: The domain over which the evaluations are defined.
    ///
    /// returns: The quotient evaluation result.
    pub fn compute_quotient_evaluation(
        evaluations: &PlookupEvaluations<F>,
        beta: &F,
        gamma: &F,
        evaluation_challenge: &F,
        domain: &Radix2EvaluationDomain<F>,
    ) -> F {
        let one = F::one();
        // g^n
        let gn = domain.elements().last().unwrap();
        // These evaluations are computed in O(|domain|) time
        let lagrange_evaluations = domain.evaluate_all_lagrange_coefficients(*evaluation_challenge);
        // L_0(x);
        let l0_eval = lagrange_evaluations[0];
        // L_n(x);
        let ln_eval = lagrange_evaluations.last().unwrap();

        // (Z(x) - 1) * (L_0(x) + L_n(x))
        let z1_zn_equal_one_eval = (evaluations.z - one) * (l0_eval + ln_eval);

        // L_n(x) * (h1(x) - h2(g*x))
        let last_h1_equal_first_h2_eval = *ln_eval * (evaluations.h1 - evaluations.h2_g);

        // (x - g^n) * Z(X) * (1 + beta) * (gamma + f(x)) * (gamma * (1 + beta) + t(x) + beta*t(gx))
        // -
        // (x - g^n) * Z(gx) * (gamma * (1 + beta) + h1(x) + beta * h1(gx)) * (gamma * (1 + beta) + h2(x) + beta * h2(gx))
        let check_z_eval: F = {
            let beta_plus_one = *beta + one;
            let gamma_mul_beta_plus_one = *gamma * beta_plus_one;

            let mut left_side = evaluations.z;
            left_side *= beta_plus_one;
            left_side *= *gamma + evaluations.f;
            left_side *= gamma_mul_beta_plus_one + evaluations.t + (*beta * evaluations.t_g);

            let mut right_side = evaluations.z_g;
            right_side *= gamma_mul_beta_plus_one + evaluations.h1 + (*beta * evaluations.h1_g);
            right_side *= gamma_mul_beta_plus_one + evaluations.h2 + (*beta * evaluations.h2_g);

            (*evaluation_challenge - gn) * (left_side - right_side)
        };

        // Evaluates vanishing polynomial at evaluation_challenge
        let v_h = domain.evaluate_vanishing_polynomial(*evaluation_challenge);

        (z1_zn_equal_one_eval + last_h1_equal_first_h2_eval + check_z_eval) / v_h
    }

    /// Checks if `Z(1) = 1` and `Z(g^n) = 1`.
    ///
    /// # Arguments
    ///
    /// * `z`
    /// * `domain`: The domain has size `n`.
    /// * `domain_2n`: The domain has size `2n`.
    ///
    /// returns: The polynomial represents above condition.
    fn check_z1_zn_equal_one(z: &Poly<F>, domain: &Domain<F>, domain_2n: &Domain<F>) -> Poly<F> {
        // L_0
        let l0 = Poly::lagrange_basis(0, domain);
        // L_n
        let ln = Poly::lagrange_basis(domain.size() - 1usize, domain);
        // (L_0(x) + L_n(x)) * (Z(x) - 1)
        let mut res = z - &Poly::from_constant(&F::one());
        res.mul_poly_over_domain_in_place(&(l0 + ln), domain_2n)
            .unwrap();
        res
    }

    /// Checks if `Z` is computed correctly.
    ///
    /// # Arguments
    ///
    /// * `f`
    /// * `t`
    /// * `h1`
    /// * `h2`
    /// * `z`
    /// * `gamma`
    /// * `beta`
    /// * `domain`: The domain has size `n`.
    /// * `domain_2n`: The domain has size `2n`.
    ///
    /// returns: The polynomial represents above condition.
    fn check_z_poly(
        f: &Poly<F>,
        t: &Poly<F>,
        h1: &Poly<F>,
        h2: &Poly<F>,
        z: &Poly<F>,
        gamma: F,
        beta: F,
        domain: &Domain<F>,
        domain_2n: &Domain<F>,
    ) -> Poly<F> {
        // g^n
        let gn = domain.element(domain.size() - 1);
        // x - g^n
        let x_minus_gn: Poly<F> = Poly::from_coefficients_vec(vec![gn.neg(), F::one()]);
        // beta + 1
        let beta_plus_one = beta + F::one();
        // gamma * (1 + beta)
        let gamma_mul_beta_plus_one = Poly::<F>::from_constant(&(gamma * beta_plus_one));
        let domain_4n = &Domain::<F>::new(domain_2n.size() * 2).unwrap();

        // Z(x) * (1 + beta) * (gamma + f(x)) * (gamma*(1 + beta) + t(x) + beta*t(gx))
        let left_side = {
            let mut left_side = z.clone();

            // The degree is n after this
            left_side.mul_scalar_in_place(&beta_plus_one);

            // The degree is 2n after this
            left_side
                .mul_poly_over_domain_in_place(&(f + &Poly::from_constant(&gamma)), domain_2n)
                .unwrap();

            // The degree is 3n after this
            let mut t_gx_beta = Self::compute_f_gx_poly(t, domain);
            t_gx_beta.mul_scalar_in_place(&beta);
            left_side
                .mul_poly_over_domain_in_place(
                    &(&gamma_mul_beta_plus_one + t + t_gx_beta),
                    domain_4n,
                )
                .unwrap();
            left_side
        };

        // Z(gx) * (gamma*(1 + beta) + h1(x) + beta*h1(gx)) * (gamma*(1 + beta) + h2(x) + beta*h2(gx))
        let right_side = {
            let mut right_side = Self::compute_f_gx_poly(z, domain);

            // The degree is 2n after this
            let mut h1_gx_beta = Self::compute_f_gx_poly(h1, domain);
            h1_gx_beta.mul_scalar_in_place(&beta);
            right_side
                .mul_poly_over_domain_in_place(
                    &(gamma_mul_beta_plus_one.clone() + h1.clone() + h1_gx_beta),
                    domain_2n,
                )
                .unwrap();

            // The degree is 3n after this
            let mut h2_gx_beta = Self::compute_f_gx_poly(h2, domain);
            h2_gx_beta.mul_scalar_in_place(&beta);
            right_side
                .mul_poly_over_domain_in_place(
                    &(gamma_mul_beta_plus_one + h2.clone() + h2_gx_beta),
                    domain_4n,
                )
                .unwrap();
            right_side
        };

        (&left_side - &right_side).naive_mul(&x_minus_gn)
    }

    /// Checks if `h1[n+1] = h2[1]`.
    ///
    /// # Arguments
    ///
    /// * `h1`
    /// * `h2`
    /// * `domain`: The domain has size `n`
    /// * `domain_2n`: The domain has size `2n`
    ///
    /// returns: The polynomial represents above condition.
    fn check_last_h1_equal_first_h2(
        h1: &Poly<F>,
        h2: &Poly<F>,
        domain: &Domain<F>,
        domain_2n: &Domain<F>,
    ) -> Poly<F> {
        let mut res = Poly::lagrange_basis(domain.size() - 1, domain);
        let h1_minus_h2 = h1 - &Self::compute_f_gx_poly(h2, domain);
        res.mul_poly_over_domain_in_place(&h1_minus_h2, domain_2n)
            .unwrap();
        res
    }

    /// Computes `f(gx)` from `f(x)` where `g` is group generator.
    ///
    /// # Arguments
    ///
    /// * `f`: The polynomial `f(x)`.
    /// * `domain`: The domain over which `f(x)` is defined.
    ///
    /// returns: The polynomial representation of `f(gx)`.
    fn compute_f_gx_poly(f: &Poly<F>, domain: &Domain<F>) -> Poly<F> {
        assert!(f.coeffs().len() <= domain.size());
        let mut g_pow = F::one();
        Poly::from_coefficients_vec(
            f.coeffs()
                .iter()
                .map(|c| {
                    let gx_c = *c * g_pow;
                    g_pow *= domain.group_gen();
                    gx_c
                })
                .collect(),
        )
    }
}

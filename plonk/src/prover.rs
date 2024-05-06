use std::ops::{Add, Div, Mul, Neg, Sub};

use ark_bls12_381::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial as Poly,
};
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial};
use digest::Digest;
use rand::prelude::StdRng;
use rand::SeedableRng;
use sha2::Sha256;

use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;

use crate::challenge::ChallengeGenerator;
use crate::compiled_circuit::CompiledCircuit;
use crate::polynomial::IntoPolynomialExt;
use crate::slice_polynomial::SlicePoly;
use crate::types::Polynomial;

/// Struct representing a proof.
pub struct Proof {
    /// Commitment of wire polynomial a(x)
    pub a_commit: KzgCommitment,
    /// Commitment of wire polynomial b(x)
    pub b_commit: KzgCommitment,
    /// Commitment of wire polynomial c(x)
    pub c_commit: KzgCommitment,
    /// Commitment of permutation polynomial z(x)
    pub z_commit: KzgCommitment,
    /// Commitment of the first part of quotient polynomial t(X)
    pub t_lo_commit: KzgCommitment,
    /// Commitment of the second part of quotient polynomial t(X)
    pub t_mid_commit: KzgCommitment,
    /// Commitment of the third part of quotient polynomial t(X)
    pub t_hi_commit: KzgCommitment,
    /// Commitment of opening proof polynomial w_ev_x
    pub w_ev_x_commit: KzgCommitment,
    /// Commitment of opening proof polynomial w_ev_wx
    pub w_ev_wx_commit: KzgCommitment,
    /// Opening evaluations of a(x)
    pub bar_a: Fr,
    /// Opening evaluations of b(x)
    pub bar_b: Fr,
    /// Opening evaluations of c(x)
    pub bar_c: Fr,
    /// Opening evaluations of s_sigma_1(x)
    pub bar_s_sigma_1: Fr,
    /// Opening evaluations of s_sigma_2(x)
    pub bar_s_sigma_2: Fr,
    /// Opening evaluations of z_w(x)
    pub bar_z_w: Fr,
    /// Multipoint evaluation challenge
    pub u: Fr,
    /// Degree of each part of quotient polynomial
    pub degree: usize,
}

pub fn generate_proof<T: Digest + Default>(compiled_circuit: &CompiledCircuit) -> Proof {
    println!("Generating proof...");

    let f_ax = compiled_circuit.gate_constraints().f_ax();
    let f_bx = compiled_circuit.gate_constraints().f_bx();
    let f_cx = compiled_circuit.gate_constraints().f_cx();
    let k1 = compiled_circuit.copy_constraints().k1();
    let k2 = compiled_circuit.copy_constraints().k2();
    let s_sigma_1 = compiled_circuit.copy_constraints().get_s_sigma_1();
    let s_sigma_2 = compiled_circuit.copy_constraints().get_s_sigma_2();
    let s_sigma_3 = compiled_circuit.copy_constraints().get_s_sigma_3();
    let q_mx = compiled_circuit.gate_constraints().q_mx();
    let q_rx = compiled_circuit.gate_constraints().q_rx();
    let q_o = compiled_circuit.gate_constraints().q_ox();
    let q_lx = compiled_circuit.gate_constraints().q_lx();
    let pi_x = compiled_circuit.gate_constraints().pi_x();
    let q_cx = compiled_circuit.gate_constraints().q_cx();

    // Round 1
    let mut rng = StdRng::seed_from_u64(0);
    let b1 = Fr::rand(&mut rng);
    let b2 = Fr::rand(&mut rng);
    let b3 = Fr::rand(&mut rng);
    let b4 = Fr::rand(&mut rng);
    let b5 = Fr::rand(&mut rng);
    let b6 = Fr::rand(&mut rng);
    let aa1 = Polynomial::from_coefficients_slice(&[b2, b1]);
    let bb1 = Polynomial::from_coefficients_slice(&[b4, b3]);
    let cc1 = Polynomial::from_coefficients_slice(&[b6, b5]);
    let domain = GeneralEvaluationDomain::<Fr>::new(compiled_circuit.size).unwrap();
    let ax = aa1.mul_by_vanishing_poly(domain) + f_ax.clone();
    let bx = bb1.mul_by_vanishing_poly(domain) + f_bx.clone();
    let cx = cc1.mul_by_vanishing_poly(domain) + f_cx.clone();

    let kzg_scheme = KzgScheme::new(compiled_circuit.srs());
    let a_commit = kzg_scheme.commit(&ax);
    let b_commit = kzg_scheme.commit(&bx);
    let c_commit = kzg_scheme.commit(&cx);

    // Round 2
    let mut challenge_generator = ChallengeGenerator::<T>::default();
    challenge_generator.feed(&a_commit);
    challenge_generator.feed(&b_commit);
    challenge_generator.feed(&c_commit);

    let [beta, gamma] = challenge_generator.generate_challenges();

    let mut acc = Fr::from(1);
    let mut accs = vec![acc];
    let elements = domain.elements();
    let _ = elements
        .take(compiled_circuit.size - 1)
        .map(|e| {
            let w_j = f_ax.evaluate(&e);
            let w_nj = f_bx.evaluate(&e);
            let w_2nj = f_cx.evaluate(&e);

            let numerator = (w_j + beta.mul(e) + gamma)
                * (w_nj + beta.mul(e).mul(k1) + gamma)
                * (w_2nj + beta.mul(e).mul(k2) + gamma);

            let s1 = s_sigma_1.evaluate(&e);
            let s2 = s_sigma_2.evaluate(&e);
            let s3 = s_sigma_3.evaluate(&e);

            let denominator = (w_j + s1 * beta + gamma)
                * (w_nj + s2 * beta + gamma)
                * (w_2nj + s3 * beta + gamma);
            acc = acc * numerator / denominator;
            accs.push(acc);
        })
        .collect::<Vec<_>>();

    let mut accs_w = accs.clone();
    accs_w.rotate_left(1);

    let b7 = Fr::rand(&mut rng);
    let b8 = Fr::rand(&mut rng);
    let b9 = Fr::rand(&mut rng);
    let zx1 = Polynomial::from_coefficients_slice(&[b9, b8, b7]);
    let zxw1 =
        Polynomial::from_coefficients_slice(&[b9, b8 * domain.element(1), b7 * domain.element(2)]);

    let ww = Evaluations::from_vec_and_domain(accs_w, domain).interpolate();
    let zxw = zxw1.mul_by_vanishing_poly(domain) + ww;

    let w = Evaluations::from_vec_and_domain(accs, domain).interpolate();
    let zx = zx1.mul_by_vanishing_poly(domain) + w;
    let z_commit = kzg_scheme.commit(&zx);
    challenge_generator.feed(&z_commit);

    // Round 3
    let [alpha] = challenge_generator.generate_challenges();
    let f_multi = ax.mul(&bx).mul(q_mx);
    let f_add = ax.mul(q_lx) + bx.clone().mul(q_rx) + cx.clone().mul(q_o);
    let first_part = f_multi + f_add + pi_x.clone() + q_cx.clone();

    let second_part = (ax.clone() + Polynomial::from_coefficients_vec(vec![gamma, beta]))
        .mul(&(bx.clone() + Polynomial::from_coefficients_vec(vec![gamma, beta * k1])))
        .mul(&(cx.clone() + Polynomial::from_coefficients_vec(vec![gamma, beta * k2])))
        .mul(&zx);
    let second_part_2 = (ax.clone() + s_sigma_1.mul(beta) + gamma.into_polynomial()).mul(
        &(bx.clone() + s_sigma_2.mul(beta) + gamma.into_polynomial())
            .mul(&(&cx + &s_sigma_3.mul(beta) + gamma.into_polynomial()))
            .mul(&zxw),
    );

    let second_part = second_part.sub(&second_part_2);
    let second_part = second_part.mul(alpha);

    let l1x = Evaluations::from_vec_and_domain(vec![Fr::from(1)], domain).interpolate();
    let third_part = (zx.clone() + Fr::from(-1).into_polynomial())
        .mul(&l1x)
        .mul(alpha.square());
    let (tx, remaining) = (first_part + second_part + third_part)
        .divide_by_vanishing_poly(domain)
        .unwrap();

    assert!(remaining.is_zero());
    let slice_poly = SlicePoly::new(tx);
    let [t_lo_commit, t_mid_commit, t_hi_commit] = slice_poly.commit(&kzg_scheme);
    challenge_generator.feed(&t_lo_commit);
    challenge_generator.feed(&t_mid_commit);
    challenge_generator.feed(&t_hi_commit);

    // Round 4
    let [evaluation_challenge] = challenge_generator.generate_challenges();
    let bar_a = ax.evaluate(&evaluation_challenge);
    let bar_b = bx.evaluate(&evaluation_challenge);
    let bar_c = cx.evaluate(&evaluation_challenge);
    let bar_s_sigma_1 = s_sigma_1.evaluate(&evaluation_challenge);
    let bar_s_sigma_2 = s_sigma_2.evaluate(&evaluation_challenge);
    let bar_z_w = zxw.evaluate(&evaluation_challenge);

    // Round 5
    challenge_generator.feed(&kzg_scheme.commit_para(bar_a));
    challenge_generator.feed(&kzg_scheme.commit_para(bar_b));
    challenge_generator.feed(&kzg_scheme.commit_para(bar_c));
    challenge_generator.feed(&kzg_scheme.commit_para(bar_s_sigma_1));
    challenge_generator.feed(&kzg_scheme.commit_para(bar_s_sigma_2));
    challenge_generator.feed(&kzg_scheme.commit_para(bar_z_w));

    let [v] = challenge_generator.generate_challenges();

    let rx_1 = q_mx.mul(bar_a * bar_b)
        + q_lx.mul(bar_a)
        + q_rx.mul(bar_b)
        + q_o.mul(bar_c)
        + pi_x.evaluate(&evaluation_challenge).into_polynomial()
        + q_cx.clone();

    let rx_2 = ((bar_a + beta * evaluation_challenge + gamma)
        * (bar_b + beta * k1 * evaluation_challenge + gamma)
        * (bar_c + beta * compiled_circuit.copy_constraints().k2() * evaluation_challenge + gamma))
        .into_polynomial()
        .mul(&zx);

    let rx_3 = &s_sigma_3
        .clone()
        .mul(beta)
        .add((bar_c + gamma).into_polynomial())
        .mul(
            (bar_a + beta * bar_s_sigma_1 + gamma)
                * (bar_b + beta * bar_s_sigma_2 + gamma)
                * bar_z_w,
        );
    let rx_23 = rx_2.sub(rx_3).mul(alpha);
    let rx_4 = zx
        .sub(&Fr::one().into_polynomial())
        .mul(l1x.evaluate(&evaluation_challenge))
        .mul(alpha.square());
    let rx_5 = slice_poly.compact(&evaluation_challenge).mul(
        &domain
            .vanishing_polynomial()
            .evaluate(&evaluation_challenge)
            .into_polynomial(),
    );

    let rx = rx_1.add(rx_23).add(rx_4).sub(&rx_5);

    let wx = (rx
        + ax.sub(&bar_a.into_polynomial()).mul(v)
        + bx.sub(&bar_b.into_polynomial()).mul(v.square())
        + cx.sub(&bar_c.into_polynomial()).mul(v * v * v)
        + s_sigma_1
            .sub(&bar_s_sigma_1.into_polynomial())
            .mul(v * v * v * v)
        + s_sigma_2
            .sub(&bar_s_sigma_2.into_polynomial())
            .mul(v * v * v * v * v))
    .div(&DensePolynomial::from_coefficients_vec(vec![
        -evaluation_challenge,
        Fr::from(1),
    ]));
    let w_ev_x_commit = kzg_scheme.commit(&wx);

    let w_ew = &(zx + (-bar_z_w).into_polynomial())
        / (&DensePolynomial::from_coefficients_vec(vec![
            -evaluation_challenge * domain.element(1),
            Fr::from(1),
        ]));
    let w_ev_wx_commit = kzg_scheme.commit(&w_ew);

    challenge_generator.feed(&w_ev_x_commit);
    challenge_generator.feed(&w_ev_wx_commit);
    let [u] = challenge_generator.generate_challenges();

    Proof {
        a_commit,
        b_commit,
        c_commit,
        z_commit,
        t_lo_commit,
        t_mid_commit,
        t_hi_commit,
        w_ev_x_commit,
        w_ev_wx_commit,
        bar_a,
        bar_b,
        bar_c,
        bar_s_sigma_1,
        bar_s_sigma_2,
        bar_z_w,
        u,
        degree: slice_poly.get_degree(),
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::Circuit;

    use super::*;

    #[test]
    fn test() {
        // check x^2 + y^2 = z^2.
        let compile_circuit = Circuit::default()
            .add_multiplication_gate(
                (1, 0, Fr::from(3)),
                (0, 0, Fr::from(3)),
                (0, 3, Fr::from(9)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (1, 1, Fr::from(4)),
                (0, 1, Fr::from(4)),
                (1, 3, Fr::from(16)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (1, 2, Fr::from(5)),
                (0, 2, Fr::from(5)),
                (2, 3, Fr::from(25)),
                Fr::from(0),
            )
            .add_addition_gate(
                (2, 0, Fr::from(9)),
                (2, 1, Fr::from(16)),
                (2, 2, Fr::from(25)),
                Fr::from(0),
            )
            .compile()
            .unwrap();

        let proof = generate_proof::<Sha256>(&compile_circuit);
        let proof2 = generate_proof2::<Sha256>(&compile_circuit);
        assert_eq!(proof.a_commit, proof2.a_commit);
        assert_eq!(proof.b_commit, proof2.b_commit);
        assert_eq!(proof.c_commit, proof2.c_commit);
        assert_eq!(proof.z_commit, proof2.z_commit);
        assert_eq!(proof.t_lo_commit, proof2.t_lo_commit);
        assert_eq!(proof.t_mid_commit, proof2.t_mid_commit);
        assert_eq!(proof.t_hi_commit, proof2.t_hi_commit);
        assert_eq!(proof.bar_a, proof2.bar_a);
        assert_eq!(proof.bar_b, proof2.bar_b);
        assert_eq!(proof.bar_c, proof2.bar_c);
        assert_eq!(proof.bar_s_sigma_1, proof2.bar_s_sigma_1);
        assert_eq!(proof.bar_s_sigma_2, proof2.bar_s_sigma_2);
        assert_eq!(proof.bar_z_w, proof2.bar_z_w);
        assert_eq!(proof.w_ev_x_commit, proof2.w_ev_x_commit);
        assert_eq!(proof.w_ev_wx_commit, proof2.w_ev_wx_commit);
        assert_eq!(proof.u, proof2.u);
    }
}

/// Generates a proof for the compiled circuit.
pub fn generate_proof2<T: Digest + Default>(compiled_circuit: &CompiledCircuit) -> Proof {
    println!("Generating proof...");

    // Round 1
    #[cfg(test)]
    println!("ROUND 1");

    let mut rng = StdRng::seed_from_u64(0);
    let scheme = KzgScheme::new(compiled_circuit.srs().clone());
    let domain = <GeneralEvaluationDomain<Fr>>::new(compiled_circuit.size).unwrap();

    let b1 = Fr::rand(&mut rng);
    let b2 = Fr::rand(&mut rng);
    let b3 = Fr::rand(&mut rng);
    let b4 = Fr::rand(&mut rng);
    let b5 = Fr::rand(&mut rng);
    let b6 = Fr::rand(&mut rng);

    let pre1 = DensePolynomial::from_coefficients_vec(vec![b2, b1]);
    let pre2 = DensePolynomial::from_coefficients_vec(vec![b4, b3]);
    let pre3 = DensePolynomial::from_coefficients_vec(vec![b6, b5]);

    let ax = pre1.mul_by_vanishing_poly(domain);
    let ax = compiled_circuit.gate_constraints().f_ax().clone().add(ax);

    let bx = pre2.mul_by_vanishing_poly(domain);
    let bx = compiled_circuit.gate_constraints().f_bx().clone().add(bx);

    let cx = pre3.mul_by_vanishing_poly(domain);
    let cx = compiled_circuit.gate_constraints().f_cx().clone().add(cx);

    let [a_commit, b_commit, c_commit] = commit_round1(&ax, &bx, &cx, &scheme);

    // round2
    #[cfg(test)]
    println!("ROUND 2");

    let mut challenge = ChallengeGenerator::<Sha256>::default();
    challenge.feed(&a_commit);
    challenge.feed(&b_commit);
    challenge.feed(&c_commit);
    let [beta, gamma] = challenge.generate_challenges();

    let b7 = Fr::rand(&mut rng);
    let b8 = Fr::rand(&mut rng);
    let b9 = Fr::rand(&mut rng);

    let pre4 = DensePolynomial::from_coefficients_vec(vec![b9, b8, b7]);
    let pre4 = pre4.mul_by_vanishing_poly(domain);

    let w = domain.element(1);
    let pre4w = DensePolynomial::from_coefficients_vec(vec![b9, b8 * w, b7 * domain.element(2)]);
    let pre4w = pre4w.mul_by_vanishing_poly(domain);

    let (acc_x, acc_wx) = compute_acc(&beta, &gamma, &domain, compiled_circuit);
    // check z_x and z_wx
    #[cfg(test)]
    assert_eq!(acc_x.evaluate(&(w * beta)), acc_wx.evaluate(&beta));

    let z_x = pre4 + acc_x;
    let z_wx = pre4w + acc_wx;

    let z_commit = scheme.commit(&z_x);

    // check z_x and z_wx
    #[cfg(test)]
    assert_eq!(z_x.evaluate(&(w * beta)), z_wx.evaluate(&beta));

    // round 3
    #[cfg(test)]
    println!("ROUND 3");

    challenge.feed(&z_commit);
    let [alpha] = challenge.generate_challenges();

    let tx = compute_quotient_polynomial(
        &beta,
        &gamma,
        &alpha,
        &ax,
        &bx,
        &cx,
        &z_x,
        &z_wx,
        &domain,
        compiled_circuit,
    );
    // split t into 3 parts
    let slice_poly = SlicePoly::new(tx);
    let [t_lo_commit, t_mid_commit, t_hi_commit] = slice_poly.commit(&scheme);

    // round 4
    #[cfg(test)]
    println!("ROUND 4");

    challenge.feed(&t_lo_commit.clone());
    challenge.feed(&t_mid_commit.clone());
    challenge.feed(&t_hi_commit.clone());

    let [evaluation_challenge] = challenge.generate_challenges();

    let bar_a = ax.evaluate(&evaluation_challenge);
    let bar_b = bx.evaluate(&evaluation_challenge);
    let bar_c = cx.evaluate(&evaluation_challenge);
    let bar_s_sigma_1 = compiled_circuit
        .copy_constraints()
        .get_s_sigma_1()
        .evaluate(&evaluation_challenge);
    let bar_s_sigma_2 = compiled_circuit
        .copy_constraints()
        .get_s_sigma_2()
        .evaluate(&evaluation_challenge);
    let bar_z_w = z_x.evaluate(&(evaluation_challenge * w));
    let pi_e = compiled_circuit
        .gate_constraints()
        .pi_x()
        .evaluate(&evaluation_challenge);
    let tx_compact = slice_poly.compact(&evaluation_challenge);

    // round 5
    #[cfg(test)]
    println!("ROUND 5");
    challenge.feed(&scheme.commit_para(bar_a));
    challenge.feed(&scheme.commit_para(bar_b));
    challenge.feed(&scheme.commit_para(bar_c));
    challenge.feed(&scheme.commit_para(bar_s_sigma_1));
    challenge.feed(&scheme.commit_para(bar_s_sigma_2));
    challenge.feed(&scheme.commit_para(bar_z_w));

    let [v] = challenge.generate_challenges();
    let r_x = compute_linearisation_polynomial(
        &beta,
        &gamma,
        &alpha,
        &evaluation_challenge,
        &bar_a,
        &bar_b,
        &bar_c,
        &bar_s_sigma_1,
        &bar_s_sigma_2,
        &bar_z_w,
        &pi_e,
        &tx_compact,
        &z_x,
        &ax,
        &bx,
        &cx,
        &z_wx,
        &domain,
        compiled_circuit,
    );
    eprintln!("r_x = {:?}", r_x);

    let bar_r = r_x.evaluate(&evaluation_challenge);
    eprintln!("bar_r = {:?}", bar_r);

    let w_ev_x = poly_sub_para(&r_x, &bar_r)
        + poly_sub_para(&ax, &bar_a).mul(v)
        + poly_sub_para(&bx, &bar_b).mul(v.square())
        + poly_sub_para(&cx, &bar_c).mul(v * v * v)
        + poly_sub_para(
            compiled_circuit.copy_constraints().get_s_sigma_1(),
            &bar_s_sigma_1,
        )
        .mul(v * v * v * v)
        + poly_sub_para(
            compiled_circuit.copy_constraints().get_s_sigma_2(),
            &bar_s_sigma_2,
        )
        .mul(v * v * v * v * v);
    eprintln!("w_ev_x = {:?}", w_ev_x);

    // check w_ev_x
    {
        let cur = DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge, Fr::from(1)]);
        let a = DenseOrSparsePolynomial::from(w_ev_x.clone());
        let b = DenseOrSparsePolynomial::from(cur);
        let div = a.divide_with_q_and_r(&b).expect("division failed");
        assert_eq!(
            div.1,
            DensePolynomial::from_coefficients_vec(vec![]),
            "w_ev_x was computed incorrectly"
        );
    }

    let w_ev_x = w_ev_x.div(&DensePolynomial::from_coefficients_vec(vec![
        -evaluation_challenge,
        Fr::from(1),
    ]));
    let w_ev_wx = poly_sub_para(&z_x, &bar_z_w);

    // check w_ev_wx
    {
        let cur =
            DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge * w, Fr::from(1)]);
        let a = DenseOrSparsePolynomial::from(w_ev_wx.clone());
        let b = DenseOrSparsePolynomial::from(cur);
        let div = a.divide_with_q_and_r(&b).expect("division failed");
        assert_eq!(
            div.1,
            DensePolynomial::from_coefficients_vec(vec![]),
            "w_ev_wx was computed incorrectly"
        );
    }

    let w_ev_wx = w_ev_wx.div(&DensePolynomial::from_coefficients_vec(vec![
        -evaluation_challenge * w,
        Fr::from(1),
    ]));

    let w_ev_x_commit = scheme.commit(&w_ev_x);
    let w_ev_wx_commit = scheme.commit(&w_ev_wx);

    challenge.feed(&w_ev_x_commit);
    challenge.feed(&w_ev_wx_commit);
    let [u] = challenge.generate_challenges();

    Proof {
        a_commit,
        b_commit,
        c_commit,
        z_commit,
        t_lo_commit,
        t_mid_commit,
        t_hi_commit,
        w_ev_x_commit,
        w_ev_wx_commit,
        bar_a,
        bar_b,
        bar_c,
        bar_s_sigma_1,
        bar_s_sigma_2,
        bar_z_w,
        u,
        degree: slice_poly.get_degree(),
    }
}

/// Subtracts a parameter from a polynomial.
fn poly_sub_para(poly: &Polynomial, para: &Fr) -> Polynomial {
    let mut tmp = poly.clone();
    tmp.coeffs[0] -= para;
    tmp
}

fn compute_acc(
    beta: &Fr,
    gamma: &Fr,
    domain: &GeneralEvaluationDomain<Fr>,
    compiled_circuit: &CompiledCircuit,
) -> (Polynomial, Polynomial) {
    let mut acc_e = vec![Fr::from(1)];
    let mut pre_acc_e = Fr::from(1);
    let roots = domain.elements().collect::<Vec<_>>();
    let k1 = compiled_circuit.copy_constraints().k1();
    let k2 = compiled_circuit.copy_constraints().k2();
    for i in 1..compiled_circuit.size {
        let w_i_sub1 = roots.get(i - 1).unwrap();

        let numerator = (compiled_circuit
            .gate_constraints()
            .f_ax()
            .evaluate(w_i_sub1)
            + *beta * w_i_sub1
            + *gamma)
            * (compiled_circuit
                .gate_constraints()
                .f_bx()
                .evaluate(w_i_sub1)
                + *beta * k1 * w_i_sub1
                + *gamma)
            * (compiled_circuit
                .gate_constraints()
                .f_cx()
                .evaluate(w_i_sub1)
                + *beta * k2 * w_i_sub1
                + *gamma);

        let denominator = (compiled_circuit
            .gate_constraints()
            .f_ax()
            .evaluate(w_i_sub1)
            + *beta
                * compiled_circuit
                    .copy_constraints()
                    .get_s_sigma_1()
                    .evaluate(w_i_sub1)
            + *gamma)
            * (compiled_circuit
                .gate_constraints()
                .f_bx()
                .evaluate(w_i_sub1)
                + *beta
                    * compiled_circuit
                        .copy_constraints()
                        .get_s_sigma_2()
                        .evaluate(w_i_sub1)
                + *gamma)
            * (compiled_circuit
                .gate_constraints()
                .f_cx()
                .evaluate(w_i_sub1)
                + *beta
                    * compiled_circuit
                        .copy_constraints()
                        .get_s_sigma_3()
                        .evaluate(w_i_sub1)
                + *gamma);
        pre_acc_e = pre_acc_e * numerator / denominator;
        acc_e.push(pre_acc_e);
    }

    let mut acc_e_shifted = acc_e.clone();
    acc_e_shifted.rotate_left(1);

    let acc = Evaluations::from_vec_and_domain(acc_e, *domain).interpolate();
    let acc_w = Evaluations::from_vec_and_domain(acc_e_shifted, *domain).interpolate();
    (acc, acc_w)
}

/// Computes the accumulator polynomials `acc(x)` and `acc(w*x)` for a given beta, gamma, evaluation domain, and compiled circuit.
fn compute_quotient_polynomial(
    beta: &Fr,
    gamma: &Fr,
    alpha: &Fr,
    ax: &Polynomial,
    bx: &Polynomial,
    cx: &Polynomial,
    z_x: &Polynomial,
    z_wx: &Polynomial,
    domain: &GeneralEvaluationDomain<Fr>,
    compiled_circuit: &CompiledCircuit,
) -> Polynomial {
    let k1 = compiled_circuit.copy_constraints().k1();
    let k2 = compiled_circuit.copy_constraints().k2();

    let line1 = &(ax * bx) * compiled_circuit.gate_constraints().q_mx()
        + ax * compiled_circuit.gate_constraints().q_lx()
        + bx * compiled_circuit.gate_constraints().q_rx()
        + cx * compiled_circuit.gate_constraints().q_ox()
        + compiled_circuit.gate_constraints().pi_x().clone()
        + compiled_circuit.gate_constraints().q_cx().clone();
    // check line 1
    let quotient1 = divide_by_vanishing_poly(&line1, domain).expect("No remainder 1");

    let line2 = (ax.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta]))
        .mul(&(bx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta * k1])))
        .mul(&(cx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta * k2])))
        .mul(z_x)
        .mul(alpha.clone());

    let line3 = (ax.clone()
        + compiled_circuit
            .copy_constraints()
            .get_s_sigma_1()
            .mul(*beta)
        + DensePolynomial::from_coefficients_vec(vec![*gamma]))
    .mul(
        &(bx.clone()
            + compiled_circuit
                .copy_constraints()
                .get_s_sigma_2()
                .mul(*beta)
            + DensePolynomial::from_coefficients_vec(vec![*gamma])),
    )
    .mul(
        &(cx.clone()
            + compiled_circuit
                .copy_constraints()
                .get_s_sigma_3()
                .mul(*beta)
            + DensePolynomial::from_coefficients_vec(vec![*gamma])),
    )
    .mul(z_wx);
    let line3 = line3.mul(*alpha);
    let line23 = &line2 - &line3;

    // check line 23
    let quotient23 = divide_by_vanishing_poly(&line23, domain).expect("No remainder here");

    let line4 = {
        let l1 = l1_poly(domain);
        let mut zx2 = z_x.clone();
        zx2.coeffs[0] -= Fr::from(1);
        zx2.mul(&l1).mul(alpha.square())
    };
    eprintln!("line4 = {:?}", line4);
    // check line 4
    let quotient4 = divide_by_vanishing_poly(&line4, domain).expect("No remainder here");

    quotient1 + quotient23 + quotient4
}

fn divide_by_vanishing_poly<'a>(
    poly: &Polynomial,
    domain: &GeneralEvaluationDomain<Fr>,
) -> Result<Polynomial, &'a str> {
    let (result, rest) = poly.divide_by_vanishing_poly(*domain).unwrap();
    if !rest.is_zero() {
        return Err("has remainder");
    }
    Ok(result)
}

/// Divides a polynomial by the vanishing polynomial of the given domain.
/// Returns the quotient polynomial if the division is successful, otherwise returns an error indicating a remainder.
pub(crate) fn l1_poly(domain: &GeneralEvaluationDomain<Fr>) -> Polynomial {
    let n = domain.size();
    let mut l1_e = vec![Fr::from(0); n];
    l1_e[0] = Fr::from(1);
    Evaluations::from_vec_and_domain(l1_e, *domain).interpolate()
}

/// Computes the linearization polynomial for the proof generation.
/// This function computes various terms involving the provided parameters and polynomials.
fn compute_linearisation_polynomial(
    beta: &Fr,
    gamma: &Fr,
    alpha: &Fr,
    eval_challenge: &Fr,
    bar_a: &Fr,
    bar_b: &Fr,
    bar_c: &Fr,
    bar_s_sigma_1: &Fr,
    bar_s_sigma_2: &Fr,
    bar_z_w: &Fr,
    pi_e: &Fr,
    tx_compact: &Polynomial,
    z_x: &Polynomial,
    ax: &Polynomial,
    bx: &Polynomial,
    cx: &Polynomial,
    z_wx: &Polynomial,
    domain: &GeneralEvaluationDomain<Fr>,
    compiled_circuit: &CompiledCircuit,
) -> Polynomial {
    let mut line1 = compiled_circuit
        .gate_constraints()
        .q_mx()
        .mul(*bar_a * *bar_b)
        + compiled_circuit.gate_constraints().q_lx().mul(*bar_a)
        + compiled_circuit.gate_constraints().q_rx().mul(*bar_b)
        + compiled_circuit.gate_constraints().q_ox().mul(*bar_c)
        + compiled_circuit.gate_constraints().q_cx().clone();
    line1.coeffs[0] += pi_e;
    let line2 = (*bar_a + *beta * eval_challenge + gamma)
        * (*bar_b + *beta * compiled_circuit.copy_constraints().k1() * eval_challenge + gamma)
        * (*bar_c + *beta * compiled_circuit.copy_constraints().k2() * eval_challenge + gamma)
        * alpha;
    let line2 = z_x.mul(line2);

    let line3 = (*bar_a + *beta * bar_s_sigma_1 + gamma)
        * (*bar_b + *beta * bar_s_sigma_2 + gamma)
        * bar_z_w
        * alpha;

    let mut tmp2 = compiled_circuit
        .copy_constraints()
        .get_s_sigma_3()
        .mul(*beta);
    tmp2.coeffs[0] += *bar_c + gamma;
    let line3 = tmp2.mul(line3);

    // check:
    {
        let line22 = (ax.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta]))
            .mul(
                &(bx.clone()
                    + DensePolynomial::from_coefficients_vec(vec![
                        *gamma,
                        *beta * compiled_circuit.copy_constraints().k1(),
                    ])),
            )
            .mul(
                &(cx.clone()
                    + DensePolynomial::from_coefficients_vec(vec![
                        *gamma,
                        *beta * compiled_circuit.copy_constraints().k2(),
                    ])),
            )
            .mul(*alpha)
            .mul(z_x);

        let line32 = (ax.clone()
            + compiled_circuit
                .copy_constraints()
                .get_s_sigma_1()
                .mul(*beta)
            + DensePolynomial::from_coefficients_vec(vec![*gamma]))
        .mul(
            &(bx.clone()
                + compiled_circuit
                    .copy_constraints()
                    .get_s_sigma_2()
                    .mul(*beta)
                + DensePolynomial::from_coefficients_vec(vec![*gamma])),
        )
        .mul(
            &(cx.clone()
                + compiled_circuit
                    .copy_constraints()
                    .get_s_sigma_3()
                    .mul(*beta)
                + DensePolynomial::from_coefficients_vec(vec![*gamma])),
        )
        .mul(*alpha)
        .mul(z_wx);

        let diff2 = line32.evaluate(eval_challenge) - line22.evaluate(eval_challenge);
        let cur = line3.evaluate(eval_challenge) - line2.evaluate(eval_challenge);
        assert_eq!(diff2, cur, "Wrong: line2 or line3 of round 5");
    }

    let line4 = {
        let l1_e = l1_poly(domain).evaluate(eval_challenge);
        let mut zx2 = z_x.clone();
        zx2.coeffs[0] -= Fr::from(1);
        zx2.mul(l1_e).mul(alpha.square())
    };
    let line5 = {
        let z_h_e = domain.evaluate_vanishing_polynomial(*eval_challenge);
        tx_compact.mul(z_h_e)
    };

    let r_x = line1 + line2 + (-line3) + line4 + (-line5);
    r_x
}

/// Computes the commitments for round 1 of the proof generation process.
fn commit_round1(
    ax: &Polynomial,
    bx: &Polynomial,
    cx: &Polynomial,
    scheme: &KzgScheme,
) -> [KzgCommitment; 3] {
    let c_ax = scheme.commit(ax);
    let c_bx = scheme.commit(bx);
    let c_cx = scheme.commit(cx);
    [c_ax, c_bx, c_cx]
}

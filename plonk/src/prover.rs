use std::ops::{Add, Div, Mul};

use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial as Poly};
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial};
use digest::Digest;
use sha2::Sha256;

use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;

use crate::challenge::ChallengeGenerator;
use crate::compiled_circuit::CompiledCircuit;
use crate::slice_polynomial::SlicePoly;
use crate::types::Polynomial;

pub struct Proof {
    pub a_commit: KzgCommitment,
    pub b_commit: KzgCommitment,
    pub c_commit: KzgCommitment,
    pub z_commit: KzgCommitment,
    pub t_lo_commit: KzgCommitment,
    pub t_mid_commit: KzgCommitment,
    pub t_hi_commit: KzgCommitment,
    pub w_ev_x_commit: KzgCommitment,
    pub w_ev_wx_commit: KzgCommitment,
    pub bar_a: Fr,
    pub bar_b: Fr,
    pub bar_c: Fr,
    pub bar_s_sigma_1: Fr,
    pub bar_s_sigma_2: Fr,
    pub bar_z_w: Fr,
    pub u: Fr,
    pub degree: usize,
}

pub fn generate_proof<T: Digest + Default>(compiled_circuit: &CompiledCircuit) -> Proof {
    println!("Generating proof...");

    // Round 1
    #[cfg(test)]
    println!("ROUND 1");

    let mut rng = rand::thread_rng();
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

    let [a_commit, b_commit, c_commit ] = commit_round1(&ax, &bx, &cx, &scheme);

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

    let tx = compute_quotient_polynomial(&beta, &gamma, &alpha, &ax, &bx, &cx, &z_x, &z_wx, &domain, compiled_circuit);
    // split t into 3 parts
    let slice_poly = SlicePoly::new(tx, domain.size());
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
    let bar_s_sigma_1 = compiled_circuit.copy_constraints().get_s_sigma_1().evaluate(&evaluation_challenge);
    let bar_s_sigma_2 = compiled_circuit.copy_constraints().get_s_sigma_2().evaluate(&evaluation_challenge);
    let bar_z_w = z_x.evaluate(&(evaluation_challenge * w));
    let pi_e = compiled_circuit.gate_constraints().pi_x().evaluate(&evaluation_challenge);
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
    let r_x = compute_linearisation_polynomial(&beta, &gamma, &alpha, &evaluation_challenge, &bar_a, &bar_b, &bar_c,
                                               &bar_s_sigma_1, &bar_s_sigma_2, &bar_z_w, &pi_e, &tx_compact, &z_x, &ax, &bx, &cx, &z_wx, &domain, compiled_circuit);
    let bar_r = r_x.evaluate(&evaluation_challenge);

    let w_ev_x = poly_sub_para(&r_x, &bar_r) + poly_sub_para(&ax, &bar_a).mul(v) + poly_sub_para(&bx, &bar_b).mul(v.square())
        + poly_sub_para(&cx, &bar_c).mul(v * v * v) + poly_sub_para(compiled_circuit.copy_constraints().get_s_sigma_1(), &bar_s_sigma_1).mul(v * v * v * v)
        + poly_sub_para(compiled_circuit.copy_constraints().get_s_sigma_2(), &bar_s_sigma_2).mul(v * v * v * v * v);

    // check w_ev_x
    {
        let cur = DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge, Fr::from(1)]);
        let a = DenseOrSparsePolynomial::from(w_ev_x.clone());
        let b = DenseOrSparsePolynomial::from(cur);
        let div = a.divide_with_q_and_r(&b).expect("division failed");
        assert_eq!(div.1, DensePolynomial::from_coefficients_vec(vec![]), "w_ev_x was computed incorrectly");
    }

    let w_ev_x = w_ev_x.div(&DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge, Fr::from(1)]));
    let w_ev_wx = poly_sub_para(&z_x, &bar_z_w);

    // check w_ev_wx
    {
        let cur = DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge * w, Fr::from(1)]);
        let a = DenseOrSparsePolynomial::from(w_ev_wx.clone());
        let b = DenseOrSparsePolynomial::from(cur);
        let div = a.divide_with_q_and_r(&b).expect("division failed");
        assert_eq!(div.1, DensePolynomial::from_coefficients_vec(vec![]), "w_ev_wx was computed incorrectly");
    }

    let w_ev_wx = w_ev_wx.div(&DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge * w, Fr::from(1)]));

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

fn poly_sub_para(poly: &Polynomial, para: &Fr) -> Polynomial {
    let mut tmp = poly.clone();
    tmp.coeffs[0] -= para;
    tmp
}

fn compute_acc(beta: &Fr, gamma: &Fr, domain: &GeneralEvaluationDomain<Fr>, compiled_circuit: &CompiledCircuit) -> (Polynomial, Polynomial) {
    let mut acc_e = vec![Fr::from(1)];
    let mut pre_acc_e = Fr::from(1);
    let roots = domain.elements().collect::<Vec<_>>();
    let k1 = compiled_circuit.copy_constraints().k1();
    let k2 = compiled_circuit.copy_constraints().k2();

    for i in 1..compiled_circuit.size {
        let w_i_sub1 = roots.get(i - 1).unwrap();

        let numerator = (compiled_circuit.gate_constraints().f_ax().evaluate(w_i_sub1) + *beta * w_i_sub1 + *gamma)
            * (compiled_circuit.gate_constraints().f_bx().evaluate(w_i_sub1) + *beta * k1 * w_i_sub1 + *gamma)
            * (compiled_circuit.gate_constraints().f_cx().evaluate(w_i_sub1) + *beta * k2 * w_i_sub1 + *gamma);

        let denominator =
            (compiled_circuit.gate_constraints().f_ax().evaluate(w_i_sub1) + *beta * compiled_circuit.copy_constraints().get_s_sigma_1().evaluate(w_i_sub1) + *gamma)
                * (compiled_circuit.gate_constraints().f_bx().evaluate(w_i_sub1) + *beta * compiled_circuit.copy_constraints().get_s_sigma_2().evaluate(w_i_sub1) + *gamma)
                * (compiled_circuit.gate_constraints().f_cx().evaluate(w_i_sub1) + *beta * compiled_circuit.copy_constraints().get_s_sigma_3().evaluate(w_i_sub1) + *gamma);

        pre_acc_e = pre_acc_e * numerator / denominator;
        acc_e.push(pre_acc_e);
    }


    let mut acc_e_shifted = acc_e.clone();
    acc_e_shifted.rotate_left(1);

    let acc = Evaluations::from_vec_and_domain(acc_e, *domain).interpolate();
    let acc_w = Evaluations::from_vec_and_domain(acc_e_shifted, *domain).interpolate();
    (acc, acc_w)
}

fn compute_quotient_polynomial(beta: &Fr, gamma: &Fr, alpha: &Fr, ax: &Polynomial, bx: &Polynomial, cx: &Polynomial,
                               z_x: &Polynomial, z_wx: &Polynomial, domain: &GeneralEvaluationDomain<Fr>, compiled_circuit: &CompiledCircuit) -> Polynomial {
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

    let line3 = (ax.clone() + compiled_circuit.copy_constraints().get_s_sigma_1().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma]))
        .mul(&(bx.clone() + compiled_circuit.copy_constraints().get_s_sigma_2().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
        .mul(&(cx.clone() + compiled_circuit.copy_constraints().get_s_sigma_3().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
        .mul(z_wx)
        .mul(alpha.clone());

    let line23 = &line2 - &line3;

    // check line 23
    let quotient23 = divide_by_vanishing_poly(&line23, domain).expect("No remainder here");

    let line4 = {
        let l1 = l1_poly(domain);
        let mut zx2 = z_x.clone();
        zx2.coeffs[0] -= Fr::from(1);
        zx2.mul(&l1).mul(alpha.square())
    };

    // check line 4
    let quotient4 = divide_by_vanishing_poly(&line4, domain).expect("No remainder here");

    quotient1 + quotient23 + quotient4
}

fn divide_by_vanishing_poly<'a>(poly: &Polynomial, domain: &GeneralEvaluationDomain<Fr>) -> Result<Polynomial, &'a str> {
    let (result, rest) = poly.divide_by_vanishing_poly(*domain).unwrap();
    if !rest.is_zero() {
        return Err("has remainder");
    }
    Ok(result)
}

pub(crate) fn l1_poly(domain: &GeneralEvaluationDomain<Fr>) -> Polynomial {
    let n = domain.size();
    let mut l1_e = vec![Fr::from(0); n];
    l1_e[0] = Fr::from(1);
    Evaluations::from_vec_and_domain(l1_e, *domain).interpolate()
}

fn compute_linearisation_polynomial(beta: &Fr, gamma: &Fr, alpha: &Fr, eval_challenge: &Fr,
                                    bar_a: &Fr, bar_b: &Fr, bar_c: &Fr, bar_s_sigma_1: &Fr,
                                    bar_s_sigma_2: &Fr, bar_z_w: &Fr, pi_e: &Fr, tx_compact: &Polynomial,
                                    z_x: &Polynomial, ax: &Polynomial, bx: &Polynomial, cx: &Polynomial, z_wx: &Polynomial,
                                    domain: &GeneralEvaluationDomain<Fr>, compiled_circuit: &CompiledCircuit) -> Polynomial
{
    let mut line1 = compiled_circuit.gate_constraints().q_mx().mul(*bar_a * *bar_b) + compiled_circuit.gate_constraints().q_lx().mul(*bar_a)
        + compiled_circuit.gate_constraints().q_rx().mul(*bar_b) + compiled_circuit.gate_constraints().q_ox().mul(*bar_c)
        + compiled_circuit.gate_constraints().q_cx().clone();
    line1.coeffs[0] += pi_e;

    let line2 = (*bar_a + *beta * eval_challenge + gamma) * (*bar_b + *beta * compiled_circuit.copy_constraints().k1() * eval_challenge + gamma)
        * (*bar_c + *beta * compiled_circuit.copy_constraints().k2() * eval_challenge + gamma) * alpha;
    let line2 = z_x.mul(line2);

    let line3 = (*bar_a + *beta * bar_s_sigma_1 + gamma) * (*bar_b + *beta * bar_s_sigma_2 + gamma) * bar_z_w * alpha;
    let mut tmp2 = compiled_circuit.copy_constraints().get_s_sigma_3().mul(*beta);
    tmp2.coeffs[0] += *bar_c + gamma;
    let line3 = tmp2.mul(line3);


    // check:
    {
        let line22 = (ax.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta]))
            .mul(&(bx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta * compiled_circuit.copy_constraints().k1()])))
            .mul(&(cx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta * compiled_circuit.copy_constraints().k2()])))
            .mul(*alpha)
            .mul(z_x);

        let line32 = (ax.clone() + compiled_circuit.copy_constraints().get_s_sigma_1().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma]))
            .mul(&(bx.clone() + compiled_circuit.copy_constraints().get_s_sigma_2().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
            .mul(&(cx.clone() + compiled_circuit.copy_constraints().get_s_sigma_3().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
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

fn commit_round1(ax: &Polynomial, bx: &Polynomial, cx: &Polynomial, scheme: &KzgScheme) -> [KzgCommitment; 3] {
    let c_ax = scheme.commit(ax);
    let c_bx = scheme.commit(bx);
    let c_cx = scheme.commit(cx);
    [c_ax, c_bx, c_cx]
}

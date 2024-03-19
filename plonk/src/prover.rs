use std::ops::{Add, Div, Mul};

use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Polynomial as Poly, UVPolynomial};
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial};

use kzg::{KzgCommitment, KzgScheme};

use crate::{CompiledCircuit, Polynomial};
use crate::challenge::ChallengeParse;
use crate::slice_polynomial::SlidePoly;

pub(crate) struct Proof {
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
    pub bar_ssigma_1: Fr,
    pub bar_ssigma_2: Fr,
    pub bar_z_w: Fr,
    pub u: Fr,
    pub degree: usize,
}

impl CompiledCircuit {
    pub fn prove(&self) -> Proof {
        println!("Generating proof...");

        // Round 1
        #[cfg(test)]
        println!("ROUND 1");

        let mut rng = rand::thread_rng();
        let scheme = KzgScheme::new(&self.srs);

        let b1 = Fr::rand(&mut rng);
        let b2 = Fr::rand(&mut rng);
        let b3 = Fr::rand(&mut rng);
        let b4 = Fr::rand(&mut rng);
        let b5 = Fr::rand(&mut rng);
        let b6 = Fr::rand(&mut rng);

        let pre1 = DensePolynomial::from_coefficients_vec(vec![b2, b1]);
        let pre2 = DensePolynomial::from_coefficients_vec(vec![b4, b3]);
        let pre3 = DensePolynomial::from_coefficients_vec(vec![b6, b5]);


        let ax = pre1.mul_by_vanishing_poly(self.domain);
        let ax = self.gate_constraint.get_f_ax().clone().add(ax);

        let bx = pre2.mul_by_vanishing_poly(self.domain);
        let bx = self.gate_constraint.get_f_bx().clone().add(bx);

        let cx = pre3.mul_by_vanishing_poly(self.domain);
        let cx = self.gate_constraint.get_f_cx().clone().add(cx);


        let commitments = Self::commit_round1(&ax, &bx, &cx, &scheme);


        // round2
        #[cfg(test)]
        println!("ROUND 2");

        let mut challenge = ChallengeParse::with_digest(&commitments);
        let [beta, gamma] = challenge.generate_challenges();

        let b7 = Fr::rand(&mut rng);
        let b8 = Fr::rand(&mut rng);
        let b9 = Fr::rand(&mut rng);

        let w = self.domain.element(1);
        let pre4 = DensePolynomial::from_coefficients_vec(vec![b9, b8, b7]);
        let pre4 = pre4.mul_by_vanishing_poly(self.domain);

        let pre4w = DensePolynomial::from_coefficients_vec(vec![b9, b8 * w, b7 * w * w]);
        let pre4w = pre4w.mul_by_vanishing_poly(self.domain);

        let (acc_x, acc_wx) = self.compute_acc(&beta, &gamma);
        // check z_x and z_wx
        assert_eq!(acc_x.evaluate(&(w * beta)), acc_wx.evaluate(&beta));

        let z_x = pre4 + acc_x;
        let z_wx = pre4w + acc_wx;

        let z_x_commitment = scheme.commit(&z_x);

        // check z_x and z_wx
        assert_eq!(z_x.evaluate(&(w * beta)), z_wx.evaluate(&beta));

        // round 3
        #[cfg(test)]
        println!("ROUND 3");

        challenge.digest(&z_x_commitment);
        let [alpha] = challenge.generate_challenges();

        let tx = self.compute_quotient_polynomial(&beta, &gamma, &alpha, &ax, &bx, &cx, &z_x, &z_wx);
        // split t into 3 parts
        let slice_poly = SlidePoly::new(tx, self.domain.size());
        let tx_commitment = slice_poly.commit(&scheme);

        // round 4
        #[cfg(test)]
        println!("ROUND 4");

        challenge.digest(&tx_commitment[0]);
        challenge.digest(&tx_commitment[1]);
        challenge.digest(&tx_commitment[2]);

        let [evaluation_challenge] = challenge.generate_challenges();

        let bar_a = ax.evaluate(&evaluation_challenge);
        let bar_b = bx.evaluate(&evaluation_challenge);
        let bar_c = cx.evaluate(&evaluation_challenge);
        let bar_ssigma_1 = self.copy_constraint.get_ssigma_1().evaluate(&evaluation_challenge);
        let bar_ssigma_2 = self.copy_constraint.get_ssigma_2().evaluate(&evaluation_challenge);
        let bar_z_w = z_x.evaluate(&(evaluation_challenge * w));
        let pi_e = self.gate_constraint.get_pi_x().evaluate(&evaluation_challenge);
        let tx_compact = slice_poly.compact(&evaluation_challenge);

        // round 5
        println!("ROUND 5");
        challenge.digest(&scheme.commit_para(&bar_a));
        challenge.digest(&scheme.commit_para(&bar_b));
        challenge.digest(&scheme.commit_para(&bar_c));
        challenge.digest(&scheme.commit_para(&bar_ssigma_1));
        challenge.digest(&scheme.commit_para(&bar_ssigma_2));
        challenge.digest(&scheme.commit_para(&bar_z_w));

        let [v] = challenge.generate_challenges();
        let r_x = self.compute_linearisation_polynomial(&beta, &gamma, &alpha, &evaluation_challenge, &bar_a, &bar_b, &bar_c,
                                                        &bar_ssigma_1, &bar_ssigma_2, &bar_z_w, &pi_e, &tx_compact, &z_x, &ax, &bx, &cx, &z_wx);
        let bar_r = r_x.evaluate(&evaluation_challenge);

        let w_ev_x = Self::poly_sub_para(&r_x, &bar_r) + (Self::poly_sub_para(&ax, &bar_a)).mul(v) + (Self::poly_sub_para(&bx, &bar_b)).mul(v.square())
            + (Self::poly_sub_para(&cx, &bar_c)).mul(v * v * v) + (Self::poly_sub_para(self.copy_constraint.get_ssigma_1(), &bar_ssigma_1)).mul(v * v * v * v)
            + (Self::poly_sub_para(self.copy_constraint.get_ssigma_2(), &bar_ssigma_2)).mul(v * v * v * v * v);

        // check w_ev_x
        {
            let cur = DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge, Fr::from(1)]);
            let a = DenseOrSparsePolynomial::from(w_ev_x.clone());
            let b = DenseOrSparsePolynomial::from(cur);
            let div = a.divide_with_q_and_r(&b).expect("division failed");
            assert_eq!(div.1, DensePolynomial::from_coefficients_vec(vec![]), "w_ev_x was computed uncorrected");
        }

        let w_ev_x = w_ev_x.div(&DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge, Fr::from(1)]));
        let w_ev_wx = Self::poly_sub_para(&z_x, &bar_z_w);

        // check w_ev_wx
        {
            let cur = DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge * w, Fr::from(1)]);
            let a = DenseOrSparsePolynomial::from(w_ev_wx.clone());
            let b = DenseOrSparsePolynomial::from(cur);
            let div = a.divide_with_q_and_r(&b).expect("division failed");
            assert_eq!(div.1, DensePolynomial::from_coefficients_vec(vec![]), "w_ev_wx was computed uncorrected");
        }


        let w_ev_wx = w_ev_wx.div(&DensePolynomial::from_coefficients_vec(vec![-evaluation_challenge * w, Fr::from(1)]));

        let w_ev_x_commit = scheme.commit(&w_ev_x);
        let w_ev_wx_commit = scheme.commit(&w_ev_wx);

        challenge.digest(&w_ev_x_commit);
        challenge.digest(&w_ev_wx_commit);
        let [u] = challenge.generate_challenges();


        Proof {
            a_commit: commitments[0],
            b_commit: commitments[1],
            c_commit: commitments[2],
            z_commit: z_x_commitment,
            t_lo_commit: tx_commitment[0],
            t_mid_commit: tx_commitment[1],
            t_hi_commit: tx_commitment[2],
            w_ev_x_commit: w_ev_x_commit,
            w_ev_wx_commit: w_ev_wx_commit,
            bar_a: bar_a,
            bar_b: bar_b,
            bar_c: bar_c,
            bar_ssigma_1: bar_ssigma_1,
            bar_ssigma_2: bar_ssigma_2,
            bar_z_w: bar_z_w,
            u: u,
            degree: slice_poly.get_degree(),
        }
    }

    fn poly_sub_para(poly: &Polynomial, para: &Fr) -> Polynomial {
        let mut tmp = poly.clone();
        tmp.coeffs[0] -= para;
        tmp
    }


    fn compute_acc(&self, beta: &Fr, gamma: &Fr) -> (Polynomial, Polynomial) {
        let len = self.size.clone();
        let mut acc_e = vec![];
        acc_e.push(Fr::from(1));
        let mut pre_acc_e = Fr::from(1);
        let roots = self.domain.elements().collect::<Vec<_>>();
        let k1 = self.copy_constraint.get_k1();
        let k2 = self.copy_constraint.get_k2();

        for i in 1..len {
            let w_is1 = roots.get(i - 1).unwrap();

            let numerator = (self.gate_constraint.get_f_ax().evaluate(w_is1) + *beta * w_is1 + *gamma)
                * (self.gate_constraint.get_f_bx().evaluate(w_is1) + *beta * k1 * w_is1 + *gamma)
                * (self.gate_constraint.get_f_cx().evaluate(w_is1) + *beta * k2 * w_is1 + *gamma);

            let denominator =
                (self.gate_constraint.get_f_ax().evaluate(w_is1) + *beta * self.copy_constraint.get_ssigma_1().evaluate(w_is1) + *gamma)
                    * (self.gate_constraint.get_f_bx().evaluate(w_is1) + *beta * self.copy_constraint.get_ssigma_2().evaluate(w_is1) + *gamma)
                    * (self.gate_constraint.get_f_cx().evaluate(w_is1) + *beta * self.copy_constraint.get_ssigma_3().evaluate(w_is1) + *gamma);


            let tmp = numerator / denominator;
            pre_acc_e = pre_acc_e * tmp;

            acc_e.push(pre_acc_e);
        }


        let mut acc_e_shifted = acc_e.clone();
        acc_e_shifted.rotate_left(1);


        let acc = Evaluations::from_vec_and_domain(acc_e, self.domain).interpolate();
        let acc_w = Evaluations::from_vec_and_domain(acc_e_shifted, self.domain).interpolate();
        (acc, acc_w)
    }

    fn compute_quotient_polynomial(&self, beta: &Fr, gamma: &Fr, alpha: &Fr, ax: &Polynomial, bx: &Polynomial, cx: &Polynomial, z_x: &Polynomial, z_wx: &Polynomial) -> Polynomial {
        let k1 = self.copy_constraint.get_k1();
        let k2 = self.copy_constraint.get_k2();

        let line1 = self.gate_constraint.get_q_mx().naive_mul(ax).naive_mul(bx)
            + self.gate_constraint.get_q_lx().naive_mul(ax)
            + self.gate_constraint.get_q_rx().naive_mul(bx)
            + self.gate_constraint.get_q_ox().naive_mul(cx)
            + self.gate_constraint.get_pi_x().clone()
            + self.gate_constraint.get_q_cx().clone();

        // check line 1
        self.vanishes(&line1, "Wrong: line1 round 3 of generating proof");
        let (line1, _) = line1.divide_by_vanishing_poly(self.domain).unwrap();

        let line2 = (ax.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta]))
            .naive_mul(&(bx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta * k1])))
            .naive_mul(&(cx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta * k2])))
            .mul(*alpha)
            .naive_mul(z_x);

        let line3 = (ax.clone() + self.copy_constraint.get_ssigma_1().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma]))
            .naive_mul(&(bx.clone() + self.copy_constraint.get_ssigma_2().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
            .naive_mul(&(cx.clone() + self.copy_constraint.get_ssigma_3().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
            .mul(*alpha)
            .naive_mul(z_wx);

        // check the evaluation of line 2 and 3
        let tmp = self.domain.element(2);
        let line3_eval = line3.evaluate(&tmp);
        let line2_eval = line2.evaluate(&tmp);
        assert_eq!(
            line2_eval - line3_eval,
            Fr::zero(),
            "Wrong: line2 or line3 round 3 of generating proof"
        );

        let line23 = line2 + (-line3);

        // check line 23
        self.vanishes(&line23, "Wrong: line23 round 3 of generating proof");
        let (line23, _) = line23.divide_by_vanishing_poly(self.domain).unwrap();

        let line4 = {
            let l1 = self.l1_poly();
            let mut zx2 = z_x.clone();
            zx2.coeffs[0] -= Fr::from(1);
            zx2.naive_mul(&l1).mul(alpha.square())
        };

        // check line 4
        self.vanishes(&line4, "Error: Line4 Round 3");
        let (line4, _) = line4.divide_by_vanishing_poly(self.domain).unwrap();

        let quotient_polynomial = line1 + line23 + line4;
        quotient_polynomial
    }


    fn vanishes(&self, poly: &Polynomial, msg: &str) {
        let (_, rest) = poly.divide_by_vanishing_poly(self.domain).unwrap();

        #[cfg(test)]
        println!("Rest: {:?}", rest);

        assert!(rest.is_zero(), "{}", msg);
    }

    pub(crate) fn l1_poly(&self) -> Polynomial {
        let n = self.domain.size();
        let mut l1_e = vec![Fr::from(0); n];
        l1_e[0] = Fr::from(1);
        Evaluations::from_vec_and_domain(l1_e, self.domain).interpolate()
    }

    fn compute_linearisation_polynomial(&self, beta: &Fr, gamma: &Fr, alpha: &Fr, eval_challenge: &Fr,
                                        bar_a: &Fr, bar_b: &Fr, bar_c: &Fr, bar_ssigma_1: &Fr,
                                        bar_ssigma_2: &Fr, bar_z_w: &Fr, pi_e: &Fr, tx_compact: &Polynomial,
                                        z_x: &Polynomial, ax: &Polynomial, bx: &Polynomial, cx: &Polynomial, z_wx: &Polynomial) -> Polynomial
    {
        let mut line1 = self.gate_constraint.get_q_mx().mul(*bar_a * *bar_b) + self.gate_constraint.get_q_lx().mul(*bar_a)
            + self.gate_constraint.get_q_rx().mul(*bar_b) + self.gate_constraint.get_q_ox().mul(*bar_c)
            + self.gate_constraint.get_q_cx().clone();
        line1.coeffs[0] += pi_e;

        let line2 = (*bar_a + *beta * eval_challenge + gamma) * (*bar_b + *beta * self.copy_constraint.get_k1() * eval_challenge + gamma)
            * (*bar_c + *beta * self.copy_constraint.get_k2() * eval_challenge + gamma) * alpha;
        let line2 = z_x.mul(line2);

        let line3 = (*bar_a + *beta * bar_ssigma_1 + gamma) * (*bar_b + *beta * bar_ssigma_2 + gamma) * bar_z_w * alpha;
        let mut tmp2 = self.copy_constraint.get_ssigma_3().mul(*beta);
        tmp2.coeffs[0] += *bar_c + gamma;
        let line3 = tmp2.mul(line3);


        // check:
        {
            let line22 = (ax.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta]))
                .naive_mul(&(bx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta * self.copy_constraint.get_k1()])))
                .naive_mul(&(cx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta * self.copy_constraint.get_k2()])))
                .mul(*alpha)
                .naive_mul(z_x);

            let line32 = (ax.clone() + self.copy_constraint.get_ssigma_1().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma]))
                .naive_mul(&(bx.clone() + self.copy_constraint.get_ssigma_2().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
                .naive_mul(&(cx.clone() + self.copy_constraint.get_ssigma_3().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
                .mul(*alpha)
                .naive_mul(z_wx);

            let diff2 = line32.evaluate(eval_challenge) - line22.evaluate(eval_challenge);
            let cur = line3.evaluate(eval_challenge) - line2.evaluate(eval_challenge);
            assert_eq!(diff2, cur, "Wrong: line2 or line3 of round 5");
        }

        let line4 = {
            let l1_e = self.l1_poly().evaluate(eval_challenge);
            let mut zx2 = z_x.clone();
            zx2.coeffs[0] -= Fr::from(1);
            zx2.mul(l1_e).mul(alpha.square())
        };

        let line5 = {
            let z_h_e = self.domain.evaluate_vanishing_polynomial(*eval_challenge);
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
}
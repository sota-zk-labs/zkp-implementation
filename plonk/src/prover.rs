use std::ops::{Add, Div, Mul, Sub};
use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, Polynomial as Poly, UVPolynomial};
use kzg::{KzgCommitment, KzgScheme};
use crate::{challenge, CompiledCircuit, Polynomial};
use crate::challenge::ChallengeParse;
use crate::slice_polynomial::SlidePoly;

pub(crate) struct Proof {

}
impl CompiledCircuit {
    pub fn prove(&self) -> Proof {
        /// Round 1

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


        /// check
        // let vans = self.domain.vanishing_polynomial();
        // println!("Vans: {:?}", vans);
        // let roots = self.domain.elements().collect::<Vec<_>>();
        // let w = roots.get(3).unwrap();
        // println!("w is: {:?}, Vans at w: {:?}", w, vans.evaluate(&w));
        // let f_ax = self.gate_constraint.get_f_ax().clone();
        // let f_bx = self.gate_constraint.get_f_bx().clone();
        // let f_cx = self.gate_constraint.get_f_cx().clone();
        // let q_lx = self.gate_constraint.get_q_lx().clone();
        // let q_rx = self.gate_constraint.get_q_rx().clone();
        // let q_mx = self.gate_constraint.get_q_mx().clone();
        // let q_ox = self.gate_constraint.get_q_ox().clone();
        // let q_cx = self.gate_constraint.get_q_cx().clone();
        // let pi_x = self.gate_constraint.get_pi_x().clone();
        // println!("q_ox: {:?}", q_ox);
        // let tmp = f_ax.evaluate(w) * f_bx.evaluate(w) * q_mx.evaluate(w) + f_ax.evaluate(w) * q_lx.evaluate(w)
        //     + f_bx.evaluate(w) * q_rx.evaluate(w) + f_cx.evaluate(w) * q_ox.evaluate(w) + q_cx.evaluate(w) - pi_x.evaluate(w);
        //
        // println!("tmp: {:?}", tmp);


        let ax = pre1.mul_by_vanishing_poly(self.domain);
        // println!("Check ax: (1) ");
        // self.vanishes(&ax);
        // println!("Check ax: (2) ");
        // self.vanishes(self.gate_constraint.get_f_ax());

        let ax = self.gate_constraint.get_f_ax().clone().add(ax);
        // println!("Check ax: (1) ");
        // self.vanishes(&ax);

        let bx = pre2.mul_by_vanishing_poly(self.domain);
        let bx = self.gate_constraint.get_f_bx().clone().add(bx);

        let cx = pre3.mul_by_vanishing_poly(self.domain);
        let cx = self.gate_constraint.get_f_cx().clone().add(cx);



        // println!("ax: {:?}", ax);
        // println!("bx: {:?}", bx);
        // println!("cx: {:?}", cx);


        let commitments = Self::round1(&ax, &bx, &cx, &scheme);

        // println!("commitments: {:?}", commitments);

        /// round2
        println!("ROUND 2");

        let mut challenge = ChallengeParse::with_digest(&commitments);
        let [beta, gamma] = challenge.generate_challenges();

        // println!("beta: {:?}, gamma: {:?}", beta, gamma);

        let b7 = Fr::rand(&mut rng);
        let b8 = Fr::rand(&mut rng);
        let b9 = Fr::rand(&mut rng);

        let w = self.domain.element(1);
        let pre4 = DensePolynomial::from_coefficients_vec(vec![b9, b8, b7]);
        let pre4 = pre4.mul_by_vanishing_poly(self.domain);

        let pre4w = DensePolynomial::from_coefficients_vec(vec![b9, b8*w, b7*w*w]);
        let pre4w = pre4w.mul_by_vanishing_poly(self.domain);

        let (acc_x, acc_wx) = self.compute_acc(&beta, &gamma);

        // assert_eq!(acc_x.evaluate(&w.square()), acc_wx.evaluate(&w));
        // println!("{:?}, {:?}", acc_x, acc_wx);
        //
        // println!("acc evaluate at 1: {:?}", acc_x.evaluate(&Fr::from(1)));


        let z_x = pre4 + acc_x;
        let z_wx = pre4w + acc_wx;


        let z_x_commitment = scheme.commit(&z_x);

        /// check z_x and z_wx
        assert_eq!(z_x.evaluate(&w.square()), z_wx.evaluate(&w));

        /// round 3
        println!("ROUND 3");
        // let mut challenge = ChallengeParse::with_digest(&commitments);
        challenge.digest(&z_x_commitment);
        let [alpha] = challenge.generate_challenges();

        let tx = self.compute_quotient_polynomial(&beta, &gamma, &alpha, &ax, &bx, &cx, &z_x, &z_wx);
        let slice_poly = SlidePoly::new(tx, self.domain.size());
        let tx_commitment = slice_poly.commit(&scheme);


        /// round 4
        // println!("ROUND 4");
        // challenge.digest(&tx_commitment[0]);
        // challenge.digest(&tx_commitment[1]);
        // challenge.digest(&tx_commitment[2]);
        //
        // let [evaluation_challenge] = challenge.generate_challenges();
        //
        // let bar_a = scheme.open(ax.clone(), evaluation_challenge);
        // let bar_b = scheme.open(bx.clone(), evaluation_challenge);
        // let bar_c = scheme.open(cx.clone(), evaluation_challenge);
        // let bar_ssigma_1 = scheme.open(self.copy_constraint.get_ssigma_1().clone(), evaluation_challenge);
        // let bar_ssigma_2 = scheme.open(self.copy_constraint.get_ssigma_2().clone(), evaluation_challenge);        // let bar_ssigma_3 = self.copy_constraint.get_ssigma_3().evaluate(&evaluation_challenge);
        // let bar_z_w = scheme.open(z_x.clone(), evaluation_challenge * w);
        // let pi_e = self.gate_constraint.get_pi_x().evaluate(&evaluation_challenge);
        // let tx_compact = slice_poly.compact(&evaluation_challenge);
        //
        // /// round 5
        // println!("ROUND 5");
        // challenge.digest(&KzgCommitment(bar_a.0));
        // challenge.digest(&KzgCommitment(bar_b.0));
        // challenge.digest(&KzgCommitment(bar_c.0));
        // challenge.digest(&KzgCommitment(bar_ssigma_1.0));
        // challenge.digest(&KzgCommitment(bar_ssigma_2.0));
        // challenge.digest(&KzgCommitment(bar_z_w.0));
        //
        // let [v] = challenge.generate_challenges();
        // let r_x = self.compute_linearisation_polynomial(&beta, &gamma, &alpha, &evaluation_challenge,  &bar_a.1, &bar_b.1, &bar_c.1,
        //             &bar_ssigma_1.1, &bar_ssigma_2.1, &bar_z_w.1, &pi_e, &tx_compact, &z_x);






        Proof {}
    }


    fn compute_acc(&self, beta: &Fr, gamma: &Fr) -> (Polynomial, Polynomial) {
        let len = self.size.clone();
        // println!("len acc: {:?}", len);
        // let tmp =
        let mut acc_e = vec![];
         acc_e.push(Fr::from(1));
        let mut pre_acc_e = Fr::from(1);
        let roots = self.domain.elements().collect::<Vec<_>>();
        let k1 = self.copy_constraint.get_k1();
        let k2 = self.copy_constraint.get_k2();
        // println!("ACC_E: {:?}", acc_e);
        // println!("roots: {:?}", roots);
        for i in 1..len {
            // println!("i is: {:?}", i);
            let w_is1 = roots.get(i-1).unwrap();
            let w_i = roots.get(i-1).unwrap();
            // println!("w_")
            let numerator = (self.gate_constraint.get_f_ax().evaluate(w_i) + *beta * w_is1 + *gamma)
                * (self.gate_constraint.get_f_bx().evaluate(w_i) + *beta * k1 * w_is1 + *gamma)
                * (self.gate_constraint.get_f_cx().evaluate(w_i) + *beta * k2 * w_is1 + *gamma);

            let denominator =
                (self.gate_constraint.get_f_ax().evaluate(w_i) + *beta * self.copy_constraint.get_ssigma_1().evaluate(w_is1) + *gamma)
                * (self.gate_constraint.get_f_bx().evaluate(w_i) + *beta * self.copy_constraint.get_ssigma_2().evaluate(w_is1) + *gamma)
                * (self.gate_constraint.get_f_cx().evaluate(w_i) + *beta * self.copy_constraint.get_ssigma_3().evaluate(w_is1) + *gamma);


            let tmp = numerator / denominator;
            pre_acc_e = pre_acc_e * tmp;

            acc_e.push(pre_acc_e);
        }
        // println!("ACC_E: {:?}", acc_e);
        // acc_e.pop();

        // println!("ACC_E: {:?}", acc_e);


        let mut acc_e_shifted = acc_e.clone();
        acc_e_shifted.rotate_left(1);

        let acc = Evaluations::from_vec_and_domain(acc_e, self.domain).interpolate();
        let acc_w = Evaluations::from_vec_and_domain(acc_e_shifted, self.domain).interpolate();
        (acc, acc_w)


    }

    fn compute_quotient_polynomial(&self,beta: &Fr, gamma: &Fr, alpha: &Fr, ax: &Polynomial, bx: &Polynomial, cx: &Polynomial, z_x: &Polynomial, z_wx: &Polynomial) -> Polynomial {

        let k1 = self.copy_constraint.get_k1();
        let k2 = self.copy_constraint.get_k2();
        let w = self.domain.element(0);
        // println!("pi_x is: {:?}", self.gate_constraint.get_pi_x());
        let mut line1 = self.gate_constraint.get_q_mx().naive_mul(ax).naive_mul(bx)
            + self.gate_constraint.get_q_lx().naive_mul(ax)
            + self.gate_constraint.get_q_rx().naive_mul(bx)
            + self.gate_constraint.get_q_ox().naive_mul(cx)
            + self.gate_constraint.get_pi_x().clone()
            + self.gate_constraint.get_q_cx().clone();

        println!("q_m deg: {:?}", self.gate_constraint.get_q_mx().degree());
        println!("ax deg: {:?}", ax.degree());
        println!("bx deg: {:?}", bx.degree());

        // println!("eva: {:?}", line1.evaluate(&w));
        // println!("Line1 R3: ");
        /// assert line 1
        self.vanishes(&line1, "line1 round 3");
        let (line1,_) = line1.divide_by_vanishing_poly(self.domain).unwrap();

        // println!("lINE 2");
        // println!("s_sigma1 {:?}", self.copy_constraint.get_ssigma_1());

        // let cosets = vec![Fr::from(1), self.copy_constraint.get_k1().clone(), self.copy_constraint.get_k2().clone()];

        // let line22 = [ax.clone(), bx.clone(), cx.clone()]
        //     .iter()
        //     .zip(cosets)
        //     .map(|(advice, coset)| {
        //         let rhs = DensePolynomial::from_coefficients_vec(vec![*gamma, coset * beta]);
        //         advice.clone() + rhs
        //     })
        //     .reduce(|one, other| one.naive_mul(&other))
        //     .unwrap();

        let mut line2 = (ax.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta]))
            .naive_mul(&(bx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta*k1])))
            .naive_mul(&(cx.clone() + DensePolynomial::from_coefficients_vec(vec![*gamma, *beta*k2])))
            .mul(*alpha)
            .naive_mul(z_x);
        // println!("line2: {:?}", line2);
        // println!("line22: {:?}", line22);

        // println!("line22_eval: {:?}", line22_eval);
        // line2 = line2.naive_mul(z_x);

        // self.vanishes(&line2);
        // let (line2, _) = line2.divide_by_vanishing_poly(self.domain).unwrap();
        // let permutations = vec![self.copy_constraint.get_ssigma_1().clone(),
        // self.copy_constraint.get_ssigma_2().clone(), self.copy_constraint.get_ssigma_3().clone()];
        // let line33 = [ax.clone(), bx.clone(), cx.clone()]
        //     .iter()
        //     .zip(permutations)
        //     .map(|(advice, permutation)| {
        //         let gamma = DensePolynomial::from_coefficients_vec(vec![*gamma]);
        //         let perm = permutation.mul(*beta);
        //         advice.clone() + perm + gamma
        //     })
        //     .reduce(|one, other| one.naive_mul(&other))
        //     .unwrap();

        let mut line3 = (ax.clone() + self.copy_constraint.get_ssigma_1().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma]))
            .naive_mul(&(bx.clone() + self.copy_constraint.get_ssigma_2().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
            .naive_mul(&(cx.clone() + self.copy_constraint.get_ssigma_3().mul(*beta) + DensePolynomial::from_coefficients_vec(vec![*gamma])))
            .mul(*alpha)
            .naive_mul(z_wx);


        println!("zx deg: {:?}", z_x.degree());
        println!("zwx deg: {:?}", z_wx.degree());
        // println!("line33_eval: {:?}", line33_eval);
        // println!("Check Permutation");
        // println!("z_x: {:?}", z_x);

        // line3 = line3.naive_mul(z_wx);

        /// assert evaluation of line 2 and 3
        let line3_eval = line3.evaluate(&w);
        let line2_eval = line2.evaluate(&w);
        assert_eq!(
            line2_eval - line3_eval,
            Fr::zero()
        );

        let line23 = line2 + (-line3);


        // println!("line2_eval: {:?}", line2_eval);
        // println!("line3_eval: {:?}", line3_eval);

        /// assert the combination of line 2 and 3
        self.vanishes(&line23, "line23 round 3");
        let (line23, _) = line23.divide_by_vanishing_poly(self.domain).unwrap();

        println!("Line 4");
        let line4 = {
            let l1 = self.l1_poly();
            let mut zx2 = z_x.clone();
            zx2.coeffs[0] -= Fr::from(1);
            zx2.naive_mul(&l1).mul(alpha.square())
        };

        // println!("Check line 4");
        self.vanishes(&line4, "Error: Line4 Round 3");
        let (line4, _) = line4.divide_by_vanishing_poly(self.domain).unwrap();

        println!("line1: {:?}", line1);
        println!("line23: {:?}", line23);
        // println!("line3: {:?}", line3);
        println!("line4: {:?}", line4);


        let quotient_polynomial = line1 + line23 + line4;
        // let (quotient_polynomial, _) = quotient_polynomial.divide_by_vanishing_poly(self.domain).unwrap();
        println!("quotient_polynomial: {:?}", quotient_polynomial);

        quotient_polynomial


    }


    fn vanishes(&self, poly: &Polynomial, msg: &str) {
        let (_, rest) = poly.divide_by_vanishing_poly(self.domain).unwrap();
        println!("Rest: {:?}", rest);
        assert!(rest.is_zero(), "{}", msg);
    }

    fn l1_poly(&self) -> Polynomial {
        let n = self.domain.size();
        let mut l1_e = vec![Fr::from(0); n];
        l1_e[0] = Fr::from(1);
        Evaluations::from_vec_and_domain(l1_e, self.domain).interpolate()
    }

    fn compute_linearisation_polynomial(&self, beta: &Fr, gamma: &Fr, alpha: &Fr, eval_challenge: &Fr,
                                        bar_a: &Fr, bar_b: &Fr, bar_c: &Fr, bar_ssigma_1: &Fr,
                                        bar_ssigma_2: &Fr, bar_z_w: &Fr, pi_e: &Fr, tx_compact: &Polynomial,
                                        z_x: &Polynomial) -> Polynomial
    {

        let mut line1 = self.gate_constraint.get_q_mx().mul(*bar_a * *bar_b) + self.gate_constraint.get_q_lx().mul(*bar_a)
            + self.gate_constraint.get_q_rx().mul(*bar_b) + self.gate_constraint.get_q_ox().mul(*bar_c)
            + self.gate_constraint.get_q_cx().clone();
        line1.coeffs[0] += pi_e;
        let line2 = (*bar_a + *beta * eval_challenge + gamma) * (*bar_b + *beta * self.copy_constraint.get_k1() * eval_challenge + gamma)
            * (*bar_c + *beta * self.copy_constraint.get_k2() * eval_challenge + gamma) * alpha;
        let line2 = z_x.mul(line2);

        let line3 = (*bar_a + *beta * bar_ssigma_1 + gamma) * (*bar_b + *beta * bar_ssigma_2 + gamma) * bar_z_w * alpha;
        let tmp1 = line3.clone() * (*bar_c + gamma);
        let mut tmp2 = (self.copy_constraint.get_ssigma_3().mul(*beta)).mul(line3);
        let line3 = {
            tmp2.coeffs[0] += tmp1;
            tmp2
        };



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


    fn round1(ax: &Polynomial, bx: &Polynomial, cx: &Polynomial, scheme: &KzgScheme) -> [KzgCommitment; 3]{

        let c_ax = scheme.commit(ax);
        let c_bx = scheme.commit(bx);
        let c_cx = scheme.commit(cx);

        [c_ax, c_bx, c_cx]
    }

    fn round2() {}

    fn round3() {}

    fn round4() {}

    fn round5() {}
}

#[test]
fn compile_circuit_test() {
    let mut circuit = crate::circuit::Circuit::new();
    circuit.add_a_mult_gate((1,0,Fr::from(3)), (0,0,Fr::from(3)), (0,3,Fr::from(9)), Fr::from(0));
    circuit.add_a_mult_gate((1,1,Fr::from(4)), (0,1,Fr::from(4)), (1,3,Fr::from(16)), Fr::from(0));
    circuit.add_a_mult_gate((1,2,Fr::from(5)), (0,2,Fr::from(5)), (2,3,Fr::from(25)), Fr::from(0));
    circuit.add_an_add_gate((2,0,Fr::from(9)), (2,1,Fr::from(16)), (2,2,Fr::from(25)), Fr::from(0));
    // println!("Len: {}", circuit.get_len());
    let compile_circuit = circuit.compile_circuit();
    // println!("{:?}", compile_circuit);

    compile_circuit.prove();



    // assert_eq!(1, 1);

}
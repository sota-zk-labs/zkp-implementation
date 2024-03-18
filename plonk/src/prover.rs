use std::ops::Add;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use kzg::{KzgCommitment, KzgScheme};
use crate::{CompiledCircuit, Polynomial};


struct Proof {

}
impl CompiledCircuit {
    pub fn prove(&self) -> Proof {
        /// Round 1
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

        let commitments = Self::round1(&ax, &bx, &cx, &scheme);

        /// round2






        Proof {}
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
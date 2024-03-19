use std::ops::Mul;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::PairingEngine;
use ark_poly::{EvaluationDomain, Polynomial};
use kzg::{KzgCommitment, KzgScheme};
use crate::CompiledCircuit;
use crate::challenge::ChallengeParse;
use crate::prover::Proof;

impl CompiledCircuit {
    pub fn verify(&self, proof: Proof) -> bool {
        println!("Verifying...");

        #[cfg(test)]
        println!("Precompute");
        let (q_m_c, q_l_c, q_r_c, q_o_c, q_c_c, ssigma_1_c, ssigma_2_c, ssigma_3_c) = self.get_circuit_commitment();

        #[cfg(test)]
        println!("Verify challenges");

        let (alpha, beta, gamma, evaluation_challenge, v, u) = self.verify_challenges(&proof);

        assert_eq!(u, proof.u, "Verify: Challenge verification failed.");


        let scheme = KzgScheme::new(&self.srs);
        let w = self.domain.element(1);

        let z_h_e = self.domain.vanishing_polynomial().evaluate(&evaluation_challenge);
        let l_1_e = self.l1_poly().evaluate(&evaluation_challenge);
        let p_i_e = self.gate_constraint.get_pi_x().evaluate(&evaluation_challenge);


        #[cfg(test)]
        println!("Compute r0");
        let r_0 = p_i_e - l_1_e * alpha * alpha
            - alpha * (proof.bar_a + proof.bar_ssigma_1 * beta + gamma)
            * (proof.bar_b + proof.bar_ssigma_2 * beta + gamma) * (proof.bar_c + gamma) * proof.bar_z_w;

        #[cfg(test)]
        println!("Compute [D]");

        let d_line1 = q_m_c.mul(proof.bar_a * proof.bar_b) + q_l_c.mul(proof.bar_a) + q_r_c.mul(proof.bar_b)
        + q_o_c.mul(proof.bar_c) + q_c_c;

        let d_line2 = proof.z_commit.mul((proof.bar_a + beta * evaluation_challenge + gamma)
            * (proof.bar_b + beta * self.copy_constraint.get_k1() * evaluation_challenge + gamma)
            * (proof.bar_c + beta * self.copy_constraint.get_k2() * evaluation_challenge + gamma)
            * alpha + l_1_e * alpha * alpha + u);

        let d_line3 = ssigma_3_c.mul((proof.bar_a + beta * proof.bar_ssigma_1 + gamma)
            * (proof.bar_b + beta * proof.bar_ssigma_2 + gamma) * alpha * beta * proof.bar_z_w);

        let d_line4 = (proof.t_lo_commit + proof.t_mid_commit.mul(Self::power(&evaluation_challenge, proof.degree.clone() + 1) )
            + proof.t_hi_commit.mul(Self::power(&evaluation_challenge, proof.degree.clone() * 2 + 2))).mul(z_h_e);

        let d = d_line1 + d_line2 - d_line3 - d_line4;

        #[cfg(test)]
        println!("Compute [F]");

        let f = d + proof.a_commit.mul(v) + proof.b_commit.mul(v * v) + proof.c_commit.mul(v * v * v)
            + ssigma_1_c.mul(v * v * v * v) + ssigma_2_c.mul(v * v * v * v * v);

        #[cfg(test)]
        println!("Compute [E]");
        let e = -r_0 + v * proof.bar_a + v * v * proof.bar_b + v * v * v * proof.bar_c
            + v * v * v * v * proof.bar_ssigma_1 + v * v * v * v * v * proof.bar_ssigma_2 + u * proof.bar_z_w;
        let e = scheme.commit_para(&e);

        #[cfg(test)]
        println!("Compute left side of paring");

        let pairing_left_side = Bls12_381::pairing(
            (proof.w_ev_x_commit + proof.w_ev_wx_commit.mul(u)).0,
            self.srs.get_g2s_ref().clone()
        );

        #[cfg(test)]
        println!("Compute right side of paring");
        let pairing_right_side = Bls12_381::pairing(
            (proof.w_ev_x_commit.mul(evaluation_challenge) + proof.w_ev_wx_commit.mul(u * evaluation_challenge * w)
                + f - e).0,
            self.srs.get_g2_ref().clone()
        );

        #[cfg(test)]
        println!("Check pairing");

        assert_eq!(pairing_left_side,pairing_right_side, "Verify: Pairing failed, rejected");

        println!("Accepted!!!");

        return true;
    }

    fn get_circuit_commitment(&self) -> (KzgCommitment, KzgCommitment, KzgCommitment, KzgCommitment,
                                         KzgCommitment, KzgCommitment, KzgCommitment, KzgCommitment) {

        let scheme = KzgScheme::new(&self.srs);
        let q_m_c = scheme.commit(self.gate_constraint.get_q_mx());
        let q_l_c = scheme.commit(self.gate_constraint.get_q_lx());
        let q_r_c = scheme.commit(self.gate_constraint.get_q_rx());
        let q_o_c = scheme.commit(self.gate_constraint.get_q_ox());
        let q_c_c = scheme.commit(self.gate_constraint.get_q_cx());
        let ssigma1_c = scheme.commit(self.copy_constraint.get_ssigma_1());
        let ssigma2_c = scheme.commit(self.copy_constraint.get_ssigma_2());
        let ssigma3_c = scheme.commit(self.copy_constraint.get_ssigma_3());

        (q_m_c, q_l_c, q_r_c, q_o_c, q_c_c, ssigma1_c, ssigma2_c, ssigma3_c)
    }

    pub fn power(a: &Fr, n: usize) -> Fr {
        if n == 0 {
            return Fr::from(1);
        }
        let mut cur = Fr::from(1);
        if n % 2 == 1 {
            cur = a.clone();
        }

        let q = Self::power(a, n / 2);
        let res = q * q * cur;
        return res;
    }

    fn verify_challenges(&self, proof: &Proof) -> (Fr, Fr, Fr, Fr, Fr, Fr){
        let scheme = KzgScheme::new(&self.srs);
        let commitments = [proof.a_commit.clone(), proof.b_commit.clone(), proof.c_commit.clone()];
        let mut challenge = ChallengeParse::with_digest(&commitments);
        let [beta, gamma] = challenge.generate_challenges();
        challenge.digest(&proof.z_commit);
        let [alpha] = challenge.generate_challenges();
        challenge.digest(&proof.t_lo_commit);
        challenge.digest(&proof.t_mid_commit);
        challenge.digest(&proof.t_hi_commit);
        let [evaluation_challenge] = challenge.generate_challenges();

        challenge.digest(&scheme.commit_para(&proof.bar_a));
        challenge.digest(&scheme.commit_para(&proof.bar_b));
        challenge.digest(&scheme.commit_para(&proof.bar_c));
        challenge.digest(&scheme.commit_para(&proof.bar_ssigma_1));
        challenge.digest(&scheme.commit_para(&proof.bar_ssigma_2));
        challenge.digest(&scheme.commit_para(&proof.bar_z_w));
        let [v] = challenge.generate_challenges();

        challenge.digest(&proof.w_ev_x_commit);
        challenge.digest(&proof.w_ev_wx_commit);

        let [u] = challenge.generate_challenges();

        (alpha, beta, gamma, evaluation_challenge, v, u)
    }
}

#[test]
fn verifier_accepted_test_01() {
    // check x^2 + y^2 = z^2.
    let mut circuit = crate::circuit::Circuit::new();
    circuit.add_a_mult_gate((1,0,Fr::from(3)), (0,0,Fr::from(3)), (0,3,Fr::from(9)), Fr::from(0));
    circuit.add_a_mult_gate((1,1,Fr::from(4)), (0,1,Fr::from(4)), (1,3,Fr::from(16)), Fr::from(0));
    circuit.add_a_mult_gate((1,2,Fr::from(5)), (0,2,Fr::from(5)), (2,3,Fr::from(25)), Fr::from(0));
    circuit.add_an_add_gate((2,0,Fr::from(9)), (2,1,Fr::from(16)), (2,2,Fr::from(25)), Fr::from(0));
    let compile_circuit = circuit.compile_circuit();

    let proof = compile_circuit.prove();
    assert!(compile_circuit.verify(proof));
}

#[test]
#[should_panic]
fn verifier_rejected_test_01() {
    // check: x^2 + y^2 = z^2
    let mut circuit = crate::circuit::Circuit::new();
    circuit.add_a_mult_gate((1,0,Fr::from(3)), (0,0,Fr::from(3)), (0,3,Fr::from(9)), Fr::from(0));
    circuit.add_a_mult_gate((1,1,Fr::from(4)), (0,1,Fr::from(4)), (1,3,Fr::from(16)), Fr::from(0));
    circuit.add_a_mult_gate((1,2,Fr::from(5)), (0,2,Fr::from(5)), (2,3,Fr::from(25)), Fr::from(0));
    circuit.add_an_add_gate((2,0,Fr::from(9)), (2,1,Fr::from(16)), (2,2,Fr::from(20)), Fr::from(0));
    let compile_circuit = circuit.compile_circuit();

    let proof = compile_circuit.prove();
    assert!(compile_circuit.verify(proof));
}

#[test]
fn verifier_accepted_test_02() {
    // check xy + 3x^2 + xyz = 11

    let mut circuit = crate::circuit::Circuit::new();
    circuit.add_a_mult_gate((0,1,Fr::from(1)), (1,0,Fr::from(2)), (0,3,Fr::from(2)), Fr::from(0));
    circuit.add_a_mult_gate((1,1,Fr::from(1)), (0,0,Fr::from(1)), (0,2,Fr::from(1)), Fr::from(0));
    circuit.add_a_mult_gate((2,1,Fr::from(1)), (2,6,Fr::from(3)), (1,3,Fr::from(3)), Fr::from(0));
    circuit.add_an_add_gate((0,4,Fr::from(2)), (2,2,Fr::from(3)), (0,5,Fr::from(5)), Fr::from(0));

    circuit.add_a_mult_gate((2,0,Fr::from(2)), (1,4,Fr::from(3)), (1,5,Fr::from(6)), Fr::from(0));
    circuit.add_an_add_gate((2,3,Fr::from(5)), (2,4,Fr::from(6)), (2,5,Fr::from(11)), Fr::from(0));
    circuit.add_a_constant_gate((0,6, Fr::from(3)), (1,6, Fr::from(0)), (1,2, Fr::from(3)), Fr::from(0));

    let compile_circuit = circuit.compile_circuit();

    let proof = compile_circuit.prove();
    assert!(compile_circuit.verify(proof));
}

#[test]
fn verifier_accepted_test_03() {
    // check xyz = 6
    let mut circuit = crate::circuit::Circuit::new();
    circuit.add_a_mult_gate((0,0,Fr::from(1)), (1,0,Fr::from(2)), (0,1,Fr::from(2)), Fr::from(0));
    circuit.add_a_mult_gate((2,0,Fr::from(2)), (1,1,Fr::from(3)), (2,1,Fr::from(6)), Fr::from(0));

    let compile_circuit = circuit.compile_circuit();

    let proof = compile_circuit.prove();
    assert!(compile_circuit.verify(proof));
}


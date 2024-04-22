use std::ops::Mul;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, Field};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use digest::Digest;

use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;

use crate::challenge::ChallengeGenerator;
use crate::compiled_circuit::CompiledCircuit;
use crate::prover::Proof;

/// Verifies a zero-knowledge proof for a compiled circuit.
///
pub fn verify<T: Digest + Default>(
    compiled_circuit: &CompiledCircuit,
    proof: Proof,
) -> Result<(), String> {
    println!("Verifying...");

    #[cfg(test)]
    println!("Precompute");
    let (q_m_c, q_l_c, q_r_c, q_o_c, q_c_c, s_sigma_1_c, s_sigma_2_c, s_sigma_3_c) =
        get_circuit_commitment(compiled_circuit);

    #[cfg(test)]
    println!("Verify challenges");
    let (alpha, beta, gamma, evaluation_challenge, v, u) =
        verify_challenges::<T>(&proof, compiled_circuit);

    if u != proof.u {
        return Err(String::from("Verify: Challenge verification failed."));
    }

    let domain = <GeneralEvaluationDomain<Fr>>::new(compiled_circuit.size).unwrap();
    let scheme = KzgScheme::new(compiled_circuit.srs());
    let w = domain.element(1);

    let z_h_e = evaluation_challenge.pow(BigInt::new([domain.size() as u64])) - Fr::from(1);
    let l_1_e =
        z_h_e / (Fr::from(compiled_circuit.size as u128) * (evaluation_challenge - Fr::from(1)));
    let p_i_e = compiled_circuit
        .gate_constraints()
        .pi_x()
        .evaluate(&evaluation_challenge);

    #[cfg(test)]
    println!("Compute r0");
    let r_0 = p_i_e
        - l_1_e * alpha * alpha
        - alpha
            * (proof.bar_a + proof.bar_s_sigma_1 * beta + gamma)
            * (proof.bar_b + proof.bar_s_sigma_2 * beta + gamma)
            * (proof.bar_c + gamma)
            * proof.bar_z_w;

    #[cfg(test)]
    println!("Compute [D]");

    let d_line1 = q_m_c.mul(proof.bar_a * proof.bar_b)
        + q_l_c.mul(proof.bar_a)
        + q_r_c.mul(proof.bar_b)
        + q_o_c.mul(proof.bar_c)
        + q_c_c;

    let d_line2 = proof.z_commit.mul(
        (proof.bar_a + beta * evaluation_challenge + gamma)
            * (proof.bar_b
                + beta * compiled_circuit.copy_constraints().k1() * evaluation_challenge
                + gamma)
            * (proof.bar_c
                + beta * compiled_circuit.copy_constraints().k2() * evaluation_challenge
                + gamma)
            * alpha
            + l_1_e * alpha * alpha
            + u,
    );

    let d_line3 = s_sigma_3_c.mul(
        (proof.bar_a + beta * proof.bar_s_sigma_1 + gamma)
            * (proof.bar_b + beta * proof.bar_s_sigma_2 + gamma)
            * alpha
            * beta
            * proof.bar_z_w,
    );

    let d_line4 = (proof.t_lo_commit
        + proof
            .t_mid_commit
            .mul(evaluation_challenge.pow(BigInt::new([proof.degree as u64 + 1])))
        + proof
            .t_hi_commit
            .mul(evaluation_challenge.pow(BigInt::new([proof.degree as u64 * 2 + 2]))))
    .mul(z_h_e);

    let d = d_line1 + d_line2 - d_line3 - d_line4;

    #[cfg(test)]
    println!("Compute [F]");

    let f = d
        + proof.a_commit.mul(v)
        + proof.b_commit.mul(v * v)
        + proof.c_commit.mul(v * v * v)
        + s_sigma_1_c.mul(v * v * v * v)
        + s_sigma_2_c.mul(v * v * v * v * v);

    #[cfg(test)]
    println!("Compute [E]");
    let e = -r_0
        + v * proof.bar_a
        + v * v * proof.bar_b
        + v * v * v * proof.bar_c
        + v * v * v * v * proof.bar_s_sigma_1
        + v * v * v * v * v * proof.bar_s_sigma_2
        + u * proof.bar_z_w;
    let e = scheme.commit_para(e);

    #[cfg(test)]
    println!("Compute left side of paring");

    let pairing_left_side = Bls12_381::pairing(
        (proof.w_ev_x_commit.clone() + proof.w_ev_wx_commit.clone().mul(u)).0,
        compiled_circuit.srs().g2s(),
    );

    #[cfg(test)]
    println!("Compute right side of paring");
    let pairing_right_side = Bls12_381::pairing(
        (proof.w_ev_x_commit.clone().mul(evaluation_challenge)
            + proof
                .w_ev_wx_commit
                .clone()
                .mul(u * evaluation_challenge * w)
            + f
            - e)
            .0,
        compiled_circuit.srs().g2(),
    );

    #[cfg(test)]
    println!("Check pairing");

    if pairing_left_side != pairing_right_side {
        return Err(String::from("Verify: Pairing failed, rejected"));
    }

    println!("Accepted!!!");

    Ok(())
}

/// Gets commitments of the circuit via compiled_circuit
fn get_circuit_commitment(
    compiled_circuit: &CompiledCircuit,
) -> (
    KzgCommitment,
    KzgCommitment,
    KzgCommitment,
    KzgCommitment,
    KzgCommitment,
    KzgCommitment,
    KzgCommitment,
    KzgCommitment,
) {
    let scheme = KzgScheme::new(compiled_circuit.srs());
    let q_m_c = scheme.commit(compiled_circuit.gate_constraints().q_mx());
    let q_l_c = scheme.commit(compiled_circuit.gate_constraints().q_lx());
    let q_r_c = scheme.commit(compiled_circuit.gate_constraints().q_rx());
    let q_o_c = scheme.commit(compiled_circuit.gate_constraints().q_ox());
    let q_c_c = scheme.commit(compiled_circuit.gate_constraints().q_cx());
    let s_sigma1_c = scheme.commit(compiled_circuit.copy_constraints().get_s_sigma_1());
    let s_sigma2_c = scheme.commit(compiled_circuit.copy_constraints().get_s_sigma_2());
    let s_sigma3_c = scheme.commit(compiled_circuit.copy_constraints().get_s_sigma_3());

    (
        q_m_c, q_l_c, q_r_c, q_o_c, q_c_c, s_sigma1_c, s_sigma2_c, s_sigma3_c,
    )
}

/// Verifies Fiat-Shamir challenges.
fn verify_challenges<T: Digest + Default>(
    proof: &Proof,
    compiled_circuit: &CompiledCircuit,
) -> (Fr, Fr, Fr, Fr, Fr, Fr) {
    let scheme = KzgScheme::new(compiled_circuit.srs());
    let commitments = [
        proof.a_commit.clone(),
        proof.b_commit.clone(),
        proof.c_commit.clone(),
    ];
    let mut challenge = ChallengeGenerator::<T>::from_commitment(&commitments);
    let [beta, gamma] = challenge.generate_challenges();
    challenge.feed(&proof.z_commit);
    let [alpha] = challenge.generate_challenges();
    challenge.feed(&proof.t_lo_commit);
    challenge.feed(&proof.t_mid_commit);
    challenge.feed(&proof.t_hi_commit);
    let [evaluation_challenge] = challenge.generate_challenges();

    challenge.feed(&scheme.commit_para(proof.bar_a));
    challenge.feed(&scheme.commit_para(proof.bar_b));
    challenge.feed(&scheme.commit_para(proof.bar_c));
    challenge.feed(&scheme.commit_para(proof.bar_s_sigma_1));
    challenge.feed(&scheme.commit_para(proof.bar_s_sigma_2));
    challenge.feed(&scheme.commit_para(proof.bar_z_w));
    let [v] = challenge.generate_challenges();

    challenge.feed(&proof.w_ev_x_commit);
    challenge.feed(&proof.w_ev_wx_commit);

    let [u] = challenge.generate_challenges();

    (alpha, beta, gamma, evaluation_challenge, v, u)
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use crate::circuit::Circuit;
    use crate::prover::generate_proof;

    use super::*;

    #[test]
    fn verifier_accepted_test_01() {
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
        assert!(verify::<Sha256>(&compile_circuit, proof).is_ok());
    }

    #[test]
    #[should_panic]
    fn verifier_rejected_test_01() {
        // check: x^2 + y^2 = z^2
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
                (2, 2, Fr::from(20)),
                Fr::from(0),
            )
            .compile()
            .unwrap();

        let proof = generate_proof::<Sha256>(&compile_circuit);
        assert!(verify::<Sha256>(&compile_circuit, proof).is_ok());
    }

    #[test]
    fn verifier_accepted_test_02() {
        // check xy + 3x^2 + xyz = 11

        let circuit = Circuit::default()
            .add_multiplication_gate(
                (0, 1, Fr::from(1)),
                (1, 0, Fr::from(2)),
                (0, 3, Fr::from(2)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (1, 1, Fr::from(1)),
                (0, 0, Fr::from(1)),
                (0, 2, Fr::from(1)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (2, 1, Fr::from(1)),
                (2, 6, Fr::from(3)),
                (1, 3, Fr::from(3)),
                Fr::from(0),
            )
            .add_addition_gate(
                (0, 4, Fr::from(2)),
                (2, 2, Fr::from(3)),
                (0, 5, Fr::from(5)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (2, 0, Fr::from(2)),
                (1, 4, Fr::from(3)),
                (1, 5, Fr::from(6)),
                Fr::from(0),
            )
            .add_addition_gate(
                (2, 3, Fr::from(5)),
                (2, 4, Fr::from(6)),
                (2, 5, Fr::from(11)),
                Fr::from(0),
            )
            .add_constant_gate(
                (0, 6, Fr::from(3)),
                (1, 6, Fr::from(0)),
                (1, 2, Fr::from(3)),
                Fr::from(0),
            );
        let compile_circuit = circuit.compile().unwrap();

        let proof = generate_proof::<Sha256>(&compile_circuit);
        assert!(verify::<Sha256>(&compile_circuit, proof).is_ok());
    }

    #[test]
    fn verifier_accepted_test_03() {
        // check xyz = 6
        let compile_circuit = Circuit::default()
            .add_multiplication_gate(
                (0, 0, Fr::from(1)),
                (1, 0, Fr::from(2)),
                (0, 1, Fr::from(2)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (2, 0, Fr::from(2)),
                (1, 1, Fr::from(3)),
                (2, 1, Fr::from(6)),
                Fr::from(0),
            )
            .compile()
            .unwrap();

        let proof = generate_proof::<Sha256>(&compile_circuit);
        assert!(verify::<Sha256>(&compile_circuit, proof).is_ok());
    }
}

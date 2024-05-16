use ark_ff::{BigInteger, One, PrimeField, Zero};
use sha2::Sha256;
use kzg::scheme::KzgScheme;
use kzg::srs::Srs;
use kzg::types::{BaseField, ScalarField};
use nova::circuit::{AugmentedCircuit, FCircuit, State};
use nova::ivc::{IVC, IVCProof, ZkIVCProof};
use nova::r1cs::{create_trivial_pair, FInstance, FWitness, R1CS};
use nova::transcript::Transcript;
use nova::utils::{to_f_matrix, to_f_vec};

struct TestCircuit {}
impl FCircuit for TestCircuit {
    fn run(&self, z_i: &State, w_i: &FWitness) -> State {
        let x = w_i.w[0].clone();
        let res = x * x * x + x + ScalarField::from(5);
        let base_res = BaseField::from_le_bytes_mod_order(&res.into_bigint().to_bytes_le());

        State {
            state: z_i.state + base_res
        }
    }
}
fn main() {
    // (x0^3 + x0 + 5) + (x1^3 + x1 + 5) + (x2^3 + x2 + 5) + (x3^3 + x2 + 5) = 130
    // x0 = 3, x1 = 4, x2 = 1, x3 = 2

    // generate R1CS, witnesses and public input, output.
    let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3, 4, 1, 2]);
    let (matrix_a, _, _) = (r1cs.matrix_a.clone(), r1cs.matrix_b.clone(), r1cs.matrix_c.clone());

    // Trusted setup
    let domain_size = witnesses[0].len() + x[0].len() + 1;
    let srs = Srs::new(domain_size);
    let scheme = KzgScheme::new(srs);
    let x_len = x[0].len();

    // Generate witnesses and instances
    let w: Vec<FWitness> = witnesses.iter().map(|witness| FWitness::new(witness, matrix_a.len())).collect();
    let mut u: Vec<FInstance> = w.iter().zip(x).map(|(w, x)| w.commit(&scheme, &x)).collect();

    // step i
    let mut i = BaseField::zero();

    // generate trivial instance-witness pair
    let (trivial_witness, trivial_instance) = create_trivial_pair(x_len, witnesses[0].len(), &scheme);

    // generate f_circuit instance
    let f_circuit = TestCircuit{};

    // generate states
    let mut z = vec![State{state: BaseField::from(0)}; 5];
    for index in 1..5 {
        z[index] = f_circuit.run(&z[index - 1], &w[index-1]);
    }

    let mut prover_transcript;
    let mut verifier_transcript = Transcript::<Sha256>::default();

    // create F'
    let augmented_circuit = AugmentedCircuit::<Sha256, TestCircuit>::new(
        f_circuit,
        &trivial_instance,
        &z[0]
    );

    // generate IVC
    let mut ivc = IVC::<Sha256, TestCircuit> {
        scheme,
        augmented_circuit
    };

    // initialize IVC proof, zkIVCProof, folded witness and folded instance
    let mut ivc_proof = IVCProof::trivial_ivc_proof(&trivial_instance, &trivial_witness);
    let mut zk_ivc_proof = ZkIVCProof::trivial_zk_ivc_proof(&trivial_instance);
    let mut folded_witness = trivial_witness.clone();
    let mut folded_instance = trivial_instance.clone();

    let mut res;
    for step in 0..4 {
        println!("Step: {:?}", step);
        if step == 0 {
            res = ivc.augmented_circuit.run(
                &u[step],
                None,
                &w[step],
                None,
            );
        } else {
            res = ivc.augmented_circuit.run(
                &ivc_proof.u_i,
                Some(&ivc_proof.big_u_i.clone()),
                &ivc_proof.w_i,
                Some(&zk_ivc_proof.com_t.clone().unwrap())
            );
        }

        if res.is_err() {
            println!("{:?}", res);
        }
        assert!(res.is_ok());

        // verifier verify this step
        let verify = ivc.verify(&zk_ivc_proof, &mut verifier_transcript);
        if verify.is_err() {
            println!("{:?}", verify);
        }
        assert!(verify.is_ok());

        // update for next step

        if step != 3 { // do not update if we have done with IVC
            ivc.augmented_circuit.next_step();
            i = i + BaseField::one();
            assert_eq!(ivc.augmented_circuit.z_i.state, z[step + 1].state);
            prover_transcript = Transcript::<Sha256>::default();
            verifier_transcript = Transcript::<Sha256>::default();

            let hash_x = AugmentedCircuit::<Sha256, TestCircuit>::hash_io(i, &z[0], &z[step + 1], &folded_instance);
            // convert u_1_x from BaseField into ScalarField
            u[step + 1].x = vec![ScalarField::from_le_bytes_mod_order(&hash_x.into_bigint().to_bytes_le())];

            // generate ivc_proof and zkSNARK proof.
            ivc_proof = IVCProof::new(&u[step + 1], &w[step + 1], &folded_instance, &folded_witness);
            (folded_witness, folded_instance, zk_ivc_proof) = ivc.prove(&r1cs, &ivc_proof, &mut prover_transcript);
        }
    }
}

fn gen_test_values<F: PrimeField>(inputs: Vec<usize>) -> (R1CS<F>, Vec<Vec<F>>, Vec<Vec<F>>) {
    // R1CS for: x^3 + x + 5 = y (example from article
    // https://vitalik.eth.limo/general/2016/12/10/qap.html )

    let a = to_f_matrix::<F>(vec![
        vec![1, 0, 0, 0, 0, 0],
        vec![0, 1, 0, 0, 0, 0],
        vec![1, 0, 1, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 5],
    ]);
    let b = to_f_matrix::<F>(vec![
        vec![1, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0],
        vec![0, 0, 0, 0, 0, 1],
        vec![0, 0, 0, 0, 0, 1],
    ]);
    let c = to_f_matrix::<F>(vec![
        vec![0, 1, 0, 0, 0, 0],
        vec![0, 0, 1, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 0],
        vec![0, 0, 0, 0, 1, 0],
    ]);

    // generate n witnesses
    let mut w: Vec<Vec<F>> = Vec::new();
    let mut x: Vec<Vec<F>> = Vec::new();
    for input in inputs {
        let w_i = to_f_vec::<F>(vec![
            input,
            input * input,                     // x^2
            input * input * input,             // x^2 * x
            input * input * input + input,     // x^3 + x
        ]);
        w.push(w_i.clone());
        let x_i = to_f_vec::<F>(vec![input * input * input + input + 5]);  // output: x^3 + x + 5
        x.push(x_i.clone());
    }

    let r1cs = R1CS::<F> { matrix_a: a, matrix_b: b, matrix_c: c, num_io: 1, num_vars: 4 };
    (r1cs, w, x)
}
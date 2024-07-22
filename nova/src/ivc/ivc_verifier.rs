use crate::circuit::{AugmentedCircuit, FCircuit};
use crate::ivc::{ZkIVCProof, IVC};
use crate::nifs::NIFS;
use crate::transcript::Transcript;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use kzg::types::{BaseField, ScalarField};
use sha2::Digest;

#[allow(dead_code)]
impl<T: Digest + Default + ark_serialize::Write, FC: FCircuit> IVC<T, FC> {
    /// IVC verifier will do 5 steps as mentioned in constructor 4
    /// of Nova paper.
    pub fn verify(
        &mut self,
        zk_ivc_proof: &ZkIVCProof,
        verifier_transcript: &mut Transcript<T>,
    ) -> Result<(), String> {
        let i = self.augmented_circuit.i;
        let z_0 = &self.augmented_circuit.z_0;
        let z_i = &self.augmented_circuit.z_i;

        if i == BaseField::zero() {
            if z_0.state == z_i.state {
                Ok(())
            } else {
                Err(String::from("Verify failed: wrong state"))
            }
        } else {
            // 1. parse zkIVCProof = (U, u, comT, nifs_proof)

            let u_i = zk_ivc_proof.u_i.clone();
            let big_u_i = zk_ivc_proof.big_u_i.clone();
            if zk_ivc_proof.com_t.is_none() {
                return Err(String::from(
                    "Verify failed: commitment of cross term T must exist",
                ));
            }

            if zk_ivc_proof.folded_u_proof.is_none() {
                return Err(String::from("Verify failed: folding proof must exist"));
            }
            let com_t = zk_ivc_proof.com_t.clone().unwrap();
            let folded_u_proof = zk_ivc_proof.folded_u_proof.clone().unwrap();

            // 2. check that u.x = hash(i, z_0, z_i, U)
            let hash_io = AugmentedCircuit::<T, FC>::hash_io(i, z_0, z_i, &big_u_i);
            let hash_fr =
                ScalarField::from_le_bytes_mod_order(&hash_io.into_bigint().to_bytes_le());
            if u_i.x[0] != hash_fr {
                return Err(String::from("Verify failed: Public IO is wrong"));
            }

            // 3. check that u_i.comE = com_([0,...]) and u_i.u = 1
            if u_i.com_e != self.augmented_circuit.trivial_instance.com_e {
                return Err(String::from("Verify failed: Commitment of E is wrong"));
            }
            if !u_i.u.is_one() {
                return Err(String::from("Verify failed: Scalar u is wrong"));
            }

            // 4. compute U' = NIFS.V(U, u, comT)
            let big_u_out = NIFS::<T>::verifier(folded_u_proof.r, &u_i, &big_u_i, &com_t);

            // 5. verify that zkSNARK.V(U', pi_U') = 1

            NIFS::<T>::verify(
                &folded_u_proof,
                &u_i,
                &big_u_i,
                &big_u_out,
                &com_t,
                &self.scheme,
                verifier_transcript,
            )
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::circuit::State;
    use crate::ivc::IVCProof;
    use crate::nifs::nifs_verifier::gen_test_values;
    use crate::r1cs::{create_trivial_pair, FInstance, FWitness};
    use crate::transcript::Transcript;
    use kzg::scheme::KzgScheme;
    use kzg::srs::Srs;
    use sha2::Sha256;
    use std::marker::PhantomData;
    struct TestCircuit {}
    impl FCircuit for TestCircuit {
        fn run(&self, z_i: &State, w_i: &FWitness) -> State {
            let x = w_i.w[0];
            let res = x * x * x + x + ScalarField::from(5);
            // because res is in scalar field, we need to convert it into base_field
            let base_res = BaseField::from_le_bytes_mod_order(&res.into_bigint().to_bytes_le());

            State {
                state: z_i.state + base_res,
            }
        }
    }

    #[test]
    fn test_ivc() {
        // This test:  (x0^3 + x0 + 5) + (x1^3 + x1 + 5) + (x2^3 + x2 + 5) + (x3^3 + x2 + 5) = 130
        // x0 = 3, x1 = 4, x2 = 1, x3 = 2

        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3, 4, 1, 2]);
        let (matrix_a, _, _) = (
            r1cs.matrix_a.clone(),
            r1cs.matrix_b.clone(),
            r1cs.matrix_c.clone(),
        );

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);
        let x_len = x[0].len();

        // Generate witnesses and instances
        let w: Vec<FWitness> = witnesses
            .iter()
            .map(|witness| FWitness::new(witness, matrix_a.len()))
            .collect();
        let mut u: Vec<FInstance> = w
            .iter()
            .zip(x)
            .map(|(w, x)| w.commit(&scheme, &x))
            .collect();

        // step i
        let mut i = BaseField::zero();

        // generate trivial instance-witness pair
        let (trivial_witness, trivial_instance) =
            create_trivial_pair(x_len, witnesses[0].len(), &scheme);

        // generate f_circuit instance
        let f_circuit = TestCircuit {};

        // generate states
        let mut z = vec![
            State {
                state: BaseField::from(0)
            };
            5
        ];
        for index in 1..5 {
            z[index] = f_circuit.run(&z[index - 1], &w[index - 1]);
        }

        let mut prover_transcript;
        let mut verifier_transcript = Transcript::<Sha256>::default();

        // create F'
        let augmented_circuit =
            AugmentedCircuit::<Sha256, TestCircuit>::new(f_circuit, &trivial_instance, &z[0]);

        // generate IVC
        let mut ivc = IVC::<Sha256, TestCircuit> {
            scheme,
            augmented_circuit,
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
                res = ivc.augmented_circuit.run(&u[step], None, &w[step], None);
            } else {
                res = ivc.augmented_circuit.run(
                    &ivc_proof.u_i,
                    Some(&ivc_proof.big_u_i.clone()),
                    &ivc_proof.w_i,
                    Some(&zk_ivc_proof.com_t.clone().unwrap()),
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

            if step != 3 {
                // do not update if we have done with IVC
                ivc.augmented_circuit.next_step();
                i += BaseField::one();
                assert_eq!(ivc.augmented_circuit.z_i.state, z[step + 1].state);
                prover_transcript = Transcript::<Sha256>::default();
                verifier_transcript = Transcript::<Sha256>::default();

                let hash_x = AugmentedCircuit::<Sha256, TestCircuit>::hash_io(
                    i,
                    &z[0],
                    &z[step + 1],
                    &folded_instance,
                );
                // convert u_1_x from BaseField into ScalarField
                u[step + 1].x = vec![ScalarField::from_le_bytes_mod_order(
                    &hash_x.into_bigint().to_bytes_le(),
                )];

                // generate ivc_proof and zkSNARK proof.
                ivc_proof = IVCProof::new(
                    &u[step + 1],
                    &w[step + 1],
                    &folded_instance,
                    &folded_witness,
                );
                (folded_witness, folded_instance, zk_ivc_proof) =
                    ivc.prove(&r1cs, &ivc_proof, &mut prover_transcript);
            }
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_ivc_step_by_step() {
        // This test:  (x0^3 + x0 + 5) + (x1^3 + x1 + 5) + (x2^3 + x2 + 5)= 115
        // x0 = 3, x1 = 4, x2 = 1

        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3, 4, 1]);
        let (matrix_a, _, _) = (
            r1cs.matrix_a.clone(),
            r1cs.matrix_b.clone(),
            r1cs.matrix_c.clone(),
        );

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);

        let w_0 = FWitness::new(&witnesses[0], matrix_a.len());
        let w_1 = FWitness::new(&witnesses[1], matrix_a.len());
        let w_2 = FWitness::new(&witnesses[2], matrix_a.len());

        let u_0 = w_0.commit(&scheme, &x[0]);
        let mut u_1 = w_1.commit(&scheme, &x[1]);
        let mut u_2 = w_2.commit(&scheme, &x[2]);

        // step i
        let mut i = BaseField::zero();

        // generate trivial_instance
        let trivial_x = vec![ScalarField::from(0); x[0].len()];
        let trivial_witness = FWitness::new_trivial_witness(witnesses[0].len());
        let trivial_instance = trivial_witness.commit(&scheme, &trivial_x);

        // generate f_circuit instance
        let f_circuit = TestCircuit {};

        // generate state
        let z_0 = State {
            state: BaseField::from(0),
        };
        let z_1 = f_circuit.run(&z_0, &w_0);
        let z_2 = f_circuit.run(&z_1, &w_1);

        let mut prover_transcript;
        let mut verifier_transcript = Transcript::<Sha256>::default();

        // create F'
        let augmented_circuit = AugmentedCircuit::<Sha256, TestCircuit> {
            f_circuit,
            i: BaseField::zero(),
            trivial_instance: trivial_instance.clone(),
            z_0: z_0.clone(),
            z_i: z_0.clone(),
            z_i1: None,
            h_i: None,
            h_i1: None,
            phantom_data_t: PhantomData,
        };

        // generate IVC
        let mut ivc = IVC::<Sha256, TestCircuit> {
            scheme,
            augmented_circuit,
        };

        // initialize IVC proof, zkIVCProof, folded witness (W) and folded instance (U)
        let mut ivc_proof = IVCProof {
            w_i: trivial_witness.clone(),
            u_i: trivial_instance.clone(),
            big_w_i: trivial_witness.clone(),
            big_u_i: trivial_instance.clone(),
        };

        let mut zk_ivc_proof = ZkIVCProof {
            u_i: ivc_proof.u_i,
            big_u_i: ivc_proof.big_u_i,
            com_t: None,
            folded_u_proof: None,
        };

        let folded_witness;
        let folded_instance;

        println!("Step 1");
        // run F' for the first time
        // With i = 0, the instance U_i and commitment com_t do not exist.
        let res1 = ivc.augmented_circuit.run(&u_0, None, &w_0, None);

        if res1.is_err() {
            println!("Step: {:?}, {:?}", i, res1);
        }
        assert!(res1.is_ok());

        // verifier verify this step
        let result = ivc.verify(&zk_ivc_proof, &mut verifier_transcript);
        if result.is_err() {
            println!("{:?}", result);
        }
        assert!(result.is_ok());

        // update for next step
        ivc.augmented_circuit.next_step();
        i += BaseField::one();
        assert_eq!(ivc.augmented_circuit.z_i.state, BaseField::from(35));
        prover_transcript = Transcript::<Sha256>::default();
        verifier_transcript = Transcript::<Sha256>::default();

        // because all instances above are from F, not F', so we need to do this trick.
        let u_1_x =
            AugmentedCircuit::<Sha256, TestCircuit>::hash_io(i, &z_0, &z_1, &trivial_instance);
        // convert u_1_x from BaseField into ScalarField
        u_1.x = vec![ScalarField::from_le_bytes_mod_order(
            &u_1_x.into_bigint().to_bytes_le(),
        )];

        // U_1 is a trivial instance (via the paper).
        // Prover fold u_1 and U_1 into U_2.

        // generate IVC proof.
        ivc_proof = IVCProof {
            u_i: u_1.clone(),
            w_i: w_1,
            big_u_i: trivial_instance.clone(),
            big_w_i: trivial_witness.clone(),
        };

        // generate W_2, U_2 and zkIVCProof via IVC proof
        (folded_witness, folded_instance, zk_ivc_proof) =
            ivc.prove(&r1cs, &ivc_proof, &mut prover_transcript);

        println!("Step 2");
        // run F' for the second time
        let res2 = ivc.augmented_circuit.run(
            &ivc_proof.u_i,
            Some(&ivc_proof.big_u_i.clone()),
            &ivc_proof.w_i,
            Some(&zk_ivc_proof.com_t.clone().unwrap()),
        );

        if res2.is_err() {
            println!("Step: {:?}, {:?}", i, res2);
        }
        assert!(res2.is_ok());

        // verifier verify this step
        let result = ivc.verify(&zk_ivc_proof, &mut verifier_transcript);
        if result.is_err() {
            println!("{:?}", result);
        }
        assert!(result.is_ok());

        // update next step
        ivc.augmented_circuit.next_step();
        i += BaseField::one();
        prover_transcript = Transcript::<Sha256>::default();
        verifier_transcript = Transcript::<Sha256>::default();
        // check if this state is 108.
        assert_eq!(
            ivc.augmented_circuit.z_i.state,
            BaseField::from(108),
            "Wrong state"
        );

        let u_2_x =
            AugmentedCircuit::<Sha256, TestCircuit>::hash_io(i, &z_0, &z_2, &folded_instance);
        u_2.x = vec![ScalarField::from_le_bytes_mod_order(
            &u_2_x.into_bigint().to_bytes_le(),
        )];
        ivc_proof = IVCProof {
            u_i: u_2,
            w_i: w_2,
            big_u_i: folded_instance, // U_2
            big_w_i: folded_witness,  // W_2
        };

        // Compute W_3, U_3, and zkSNARK proof
        (_, _, zk_ivc_proof) = ivc.prove(&r1cs, &ivc_proof, &mut prover_transcript);

        println!("Step 3");
        // run F' for the last time
        let res3 = ivc.augmented_circuit.run(
            &ivc_proof.u_i,
            Some(&ivc_proof.big_u_i.clone()),
            &ivc_proof.w_i,
            Some(&zk_ivc_proof.com_t.clone().unwrap()),
        );

        if res3.is_err() {
            println!("Step: {:?}, {:?}", i, res3);
        }
        assert!(res3.is_ok());

        // verifier verify this step
        let result = ivc.verify(&zk_ivc_proof, &mut verifier_transcript);
        if result.is_err() {
            println!("{:?}", result);
        }
        assert!(result.is_ok());

        // update next step
        ivc.augmented_circuit.next_step();
        // check if this state is 115.
        assert_eq!(
            ivc.augmented_circuit.z_i.state,
            BaseField::from(115),
            "Wrong state"
        );
    }
}

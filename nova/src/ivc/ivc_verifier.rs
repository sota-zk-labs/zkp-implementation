use ark_ff::{BigInteger, One, PrimeField, Zero};
use sha2::Digest;
use kzg::types::{BaseField, ScalarField};
use crate::circuit::{AugmentedCircuit, FCircuit, State};
use crate::ivc::{IVC, ZkIVCProof};
use crate::nifs::NIFS;
use crate::transcript::Transcript;

impl <T: Digest + Default + ark_serialize::Write, FC: FCircuit> IVC <T, FC> {
    pub fn verify(
        &mut self,
        zk_ivc_proof: &ZkIVCProof,
        verifier_transcript: &mut Transcript<T>
    ) -> Result<(), String> {

        let i = self.augmented_circuit.i;
        let z_0 = &self.augmented_circuit.z_0;
        let z_i = &self.augmented_circuit.z_i;


        if i == BaseField::zero() {
            return if z_0.state == z_i.state {
                Ok(())
            } else {
                Err(String::from("Verify failed: wrong state"))
            }
        } else {

            // 1. parse zkIVCProof = (U, u, comT, nifs_proof)

            let u_i = zk_ivc_proof.u_i.clone();
            let big_u_i = zk_ivc_proof.big_u_i.clone();
            if zk_ivc_proof.com_t.is_none() {
                return Err(String::from("Verify failed: commitment of cross term T must exist"));
            }

            if zk_ivc_proof.folded_u_proof.is_none() {
                return Err(String::from("Verify failed: folding proof must exist"));
            }
            let com_t = zk_ivc_proof.com_t.clone().unwrap();
            let folded_u_proof = zk_ivc_proof.folded_u_proof.clone().unwrap();

            // 2. check that u.x = hash(i, z_0, z_i, U)
            println!("z_i, {:?}", z_i);
            let hash_io = AugmentedCircuit::<T, FC>::hash_io(i, z_0, z_i, &big_u_i);
            let hash_fr = ScalarField::from_le_bytes_mod_order(&hash_io.into_bigint().to_bytes_le());
            if u_i.x[0] != hash_fr {
                return Err(String::from("Verify failed: Public IO is wrong"));
            }

            // 3. check that u_i.comE = com_([0,...]) and u_i.u = 1
            if u_i.com_e != self.augmented_circuit.trivial_instance.com_e {
                return Err(String::from("Verify failed: Commitment of E is wrong"));
            }
            if ! u_i.u.is_one() {
                return Err(String::from("Verify failed: Scalar u is wrong"));
            }

            // 4. compute U' = NIFS.V(U, u, comT)
            let big_u_out = NIFS::<T>::verifier(folded_u_proof.r, &u_i, &big_u_i, &com_t);

            // 5. verify that zkSNARK.V(U', pi_U') = 1
            let res = NIFS::<T>::verify(&folded_u_proof, &u_i, &big_u_i, &big_u_out, &com_t, &self.scheme, verifier_transcript);

            res

        }
    }
}

#[cfg(test)]

mod tests {
    use std::marker::PhantomData;
    use sha2::Sha256;
    use kzg::scheme::KzgScheme;
    use kzg::srs::Srs;
    use crate::ivc::IVCProof;
    use crate::nifs::nifs_verifier::gen_test_values;
    use super::*;
    use crate::r1cs::FWitness;
    use crate::transcript::Transcript;

    struct TestCircuit {}
    impl FCircuit for TestCircuit {
        fn run(&self, z_i: &State, w_i: &FWitness) -> State {
            let x = w_i.w[1].clone();
            let res = x * x * x + x + ScalarField::from(5);
            // because res is in scalar field, we need to convert it into base_field
            let base_res = BaseField::from_le_bytes_mod_order(&res.into_bigint().to_bytes_le());

            State {
                state: z_i.state + base_res
            }
        }
    }

    #[test]
    fn test_ivc_step_by_step_1() {
        // This test:  (x1^3 + x1 + 5) + (x2^3 + x2 + 5) = 108
        // x1 = 3, x2 = 4

        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3, 4]);
        let (matrix_a, _, _) = (r1cs.matrix_a.clone(), r1cs.matrix_b.clone(), r1cs.matrix_c.clone());

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);

        let w_0 = FWitness::new(&witnesses[0], matrix_a.len());
        let w_1 = FWitness::new(&witnesses[1], matrix_a.len());

        let u_0 = w_0.commit(&scheme, &x[0]);
        let mut u_1 = w_1.commit(&scheme, &x[1]);

        let mut i = BaseField::zero();

        // generate trivial_instance
        let trivial_x = vec![ScalarField::from(0); x[0].len()];
        let trivial_witness = FWitness::new_trivial_witness(witnesses[0].len());
        let trivial_instance = trivial_witness.commit(&scheme, &trivial_x);

        let f_circuit = TestCircuit{};

        let z_0 = State{state: BaseField::from(0)};
        let z_1 = f_circuit.run(&z_0, &w_0);
        let z_2 = f_circuit.run(&z_1, &w_1);

        let mut prover_transcript = Transcript::<Sha256>::default();
        let mut verifier_transcript = Transcript::<Sha256>::default();

        let mut augmented_circuit = AugmentedCircuit::<Sha256, TestCircuit> {
            f_circuit,
            i: BaseField::zero(),
            trivial_instance: trivial_instance.clone(),
            z_0: z_0.clone(),
            z_i: z_0.clone(),
            z_i1: None,
            hash_x: None,
            hash_x_next: None,
            phantom_data_t: PhantomData
        };

        // generate IVC
        let mut ivc = IVC::<Sha256, TestCircuit> {
            scheme,
            augmented_circuit
        };

        // run F' for the first time
        // With i = 0, the instance U_i and commitment com_t do not exist.
        let res1 = ivc.augmented_circuit.run(
            &u_0,
            None,
            &w_0,
            None,
        );
        if res1.is_err() {
            println!("Step: {:?}, {:?}", i, res1);
        }

        // update for next step
        ivc.augmented_circuit.next_step();
        i = i + BaseField::one();

        let u_1_x = AugmentedCircuit::<Sha256, TestCircuit>::hash_io(i, &z_0, &z_1, &trivial_instance);
        // convert u_1_x from BaseField into ScalarField
        u_1.x = vec![ScalarField::from_le_bytes_mod_order(&u_1_x.into_bigint().to_bytes_le())];

        // U_1 is trivial instance (via the paper).
        // Prover fold u_1 and U_1 into U2.

        let ivc_proof = IVCProof{
            u_i: u_1,
            w_i: w_1,
            big_u_i: trivial_instance,
            big_w_i: trivial_witness,
        };
        let zk_ivc_proof = ivc.prove(
            &r1cs,
            &ivc_proof,
            &mut prover_transcript
        );


        // run F' for the second time
        let res2 = ivc.augmented_circuit.run(
            &ivc_proof.u_i,
            Some(&ivc_proof.big_u_i.clone()),
            &ivc_proof.w_i,
            Some(&zk_ivc_proof.com_t.clone().unwrap())
        );

        if res2.is_err() {
            println!("Step: {:?}, {:?}", i, res2);
        }

        // verifier verify the final step
        let result = ivc.verify(&zk_ivc_proof, &mut verifier_transcript);
        if result.is_err() {
            println!("{:?}", result);
        }
        assert!(result.is_ok());


        ivc.augmented_circuit.next_step();
        // check if the final state is 108.
        assert_eq!(ivc.augmented_circuit.z_i.state, BaseField::from(108), "Wrong state");

    }
}
use crate::nifs::NIFS;
use crate::r1cs::{FInstance, FWitness};
use crate::transcript::Transcript;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use kzg::commitment::KzgCommitment;
use kzg::types::{BaseField, ScalarField};
use sha2::Digest;
use std::marker::PhantomData;
use std::ops::Add;

/// State structure of IVC, which is presented in BaseField of Bsn12_381 curve
/// Todo: Implement a general version.
#[derive(Clone, Debug)]
pub struct State {
    pub state: BaseField,
}

/// trait for F circuit
pub trait FCircuit {
    // return state z_{i+1} = F(z_i, w_i)
    fn run(&self, z_i: &State, w_i: &FWitness) -> State;
}

/// F' circuit
pub struct AugmentedCircuit<T: Digest + Default + ark_serialize::Write, FC: FCircuit> {
    // F function
    pub f_circuit: FC,
    // i is the step of IVC
    pub i: BaseField,
    // trivial instance u⊥
    pub trivial_instance: FInstance,
    // The initial state z_0
    pub z_0: State,
    // The current state
    pub z_i: State,
    // The next state z_{i+1} = F(z_i, w_i).
    pub z_i1: Option<State>,
    // h_i = hash(i, z0, zi, Ui)
    pub h_i: Option<BaseField>,
    // store the next hash IO: h_{i+1} = hash(i + 1, z0, z{i+1}, U{i+1})
    pub h_i1: Option<BaseField>,
    pub phantom_data_t: PhantomData<T>,
}

#[allow(dead_code)]
impl<T: Digest + Default + ark_serialize::Write, FC: FCircuit> AugmentedCircuit<T, FC> {
    pub fn new(f_circuit: FC, trivial_instance: &FInstance, z_0: &State) -> Self {
        Self {
            f_circuit,
            i: BaseField::zero(),
            trivial_instance: trivial_instance.clone(),
            z_0: z_0.clone(),
            z_i: z_0.clone(),
            z_i1: None,
            h_i: None,
            h_i1: None,
            phantom_data_t: PhantomData,
        }
    }
    pub fn run(
        &mut self,
        u_i: &FInstance,
        big_u_i: Option<&FInstance>,
        w_i: &FWitness,
        com_t: Option<&KzgCommitment>,
    ) -> Result<BaseField, String> {
        if self.i != BaseField::from(0) {
            // check that if i > 0 then U_i and com_t must exist
            if big_u_i.is_none() || com_t.is_none() {
                return Err(String::from("Wrong parameters."));
            }

            // check that if i > 0 then the hash_x must exist
            if self.h_i.is_none() {
                return Err(String::from("The hash public IO must exist"));
            }

            // get hash_x
            let hash_x = self.h_i.unwrap();

            // 1. check that u.x =? hash_x
            // Because u_i.x is in ScalarField while hash_x is in BaseField, they need to
            // be converted into a comparable type
            // Todo: Non-native field transform

            let u_dot_x = u_i.x[0];
            let hash_fr = ScalarField::from_le_bytes_mod_order(&hash_x.into_bigint().to_bytes_le());
            if u_dot_x != hash_fr {
                return Err(String::from("Public IO is wrong "));
            }

            // 2. check that u_i.comE = com_([0,...]) and u_i.u = 1
            if u_i.com_e != self.trivial_instance.com_e {
                return Err(String::from("Commitment of E is wrong"));
            }

            if u_i.u != ScalarField::one() {
                return Err(String::from("Scalar u is wrong"));
            }

            // 3. recreate challenge r
            let mut transcript = Transcript::<T>::default();
            transcript.feed_scalar_num(u_i.u);
            transcript.feed_scalar_num(big_u_i.unwrap().u);
            transcript.feed(com_t.unwrap());
            let [r] = transcript.generate_challenges();

            // 3.compute U_{i+1}
            let big_u_i1 = NIFS::<T>::verifier(r, u_i, big_u_i.unwrap(), com_t.unwrap());

            // compute z_{i+1} = F(z_i, w_i)
            let z_i1 = self.f_circuit.run(&self.z_i, w_i);

            // compute hash
            let new_hash = Self::hash_io(self.i.add(BaseField::one()), &self.z_0, &z_i1, &big_u_i1);

            // store the next hash
            self.h_i1 = Some(new_hash);
            // store the next state
            self.z_i1 = Some(z_i1);
        } else {
            // i == 0

            // compute z_1 = F(z_0, w_i)
            let z_i1 = self.f_circuit.run(&self.z_i, w_i);

            // compute hash
            let new_hash =
                Self::hash_io(BaseField::one(), &self.z_0, &z_i1, &self.trivial_instance);

            // store the next hash
            self.h_i1 = Some(new_hash);
            // store the next state
            self.z_i1 = Some(z_i1);
        }

        // 4. output the hash
        Ok(self.h_i1.unwrap())
    }

    /// Updating F' function for the next step of IVC.
    pub fn next_step(&mut self) {
        self.z_i = self.z_i1.clone().unwrap();
        self.z_i1 = None;
        self.i += BaseField::one();
        self.h_i = self.h_i1;
        self.h_i1 = None;
    }

    /// A function computes public IO of an instance: u.x = hash(i, z0, zi, Ui).
    pub fn hash_io(i: BaseField, z_0: &State, z_i: &State, big_u_i: &FInstance) -> BaseField {
        let mut hasher = T::default();
        i.serialize_uncompressed(&mut hasher).unwrap();
        z_0.state.serialize_uncompressed(&mut hasher).unwrap();
        z_i.state.serialize_uncompressed(&mut hasher).unwrap();

        big_u_i.com_e.0.serialize_uncompressed(&mut hasher).unwrap();
        big_u_i.u.serialize_uncompressed(&mut hasher).unwrap();
        big_u_i.com_w.0.serialize_uncompressed(&mut hasher).unwrap();

        for x in &big_u_i.x {
            x.serialize_uncompressed(&mut hasher).unwrap();
        }

        let data = hasher.finalize().to_vec();
        BaseField::from_le_bytes_mod_order(&data)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test {
    use super::*;
    use crate::nifs::nifs_verifier::gen_test_values;
    use crate::r1cs::create_trivial_pair;
    use kzg::scheme::KzgScheme;
    use kzg::srs::Srs;
    use sha2::Sha256;

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
    fn test_augmented_circuit_01() {
        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3]);
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
        let u_0 = w_0.commit(&scheme, &x[0]);

        // generate trivial_instance
        let (_, trivial_instance) = create_trivial_pair(x[0].len(), witnesses[0].len(), &scheme);

        // generate f_circuit instance
        let f_circuit = TestCircuit {};

        // generate state
        let z_0 = State {
            state: BaseField::from(0),
        };
        let z_1 = State {
            state: BaseField::from(35),
        };
        // let prover_transcript = Transcript::<Sha256>::default();

        // create F'
        let mut augmented_circuit = AugmentedCircuit::<Sha256, TestCircuit> {
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

        let res1 = augmented_circuit.run(&u_0, None, &w_0, None);

        // check if F' is running
        if res1.is_err() {
            println!("{:?}", res1);
        }

        assert!(res1.is_ok());
        let hash = res1.unwrap();
        // check if the hash output is correct
        assert_eq!(
            hash,
            AugmentedCircuit::<Sha256, TestCircuit>::hash_io(
                BaseField::one(),
                &z_0,
                &z_1,
                &trivial_instance
            )
        );
        augmented_circuit.next_step();
        // check if the state produced is correct
        assert_eq!(augmented_circuit.z_i.state, z_1.state);
    }

    #[test]
    fn test_augmented_circuit_02() {
        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3, 4]);
        let (matrix_a, _, _) = (
            r1cs.matrix_a.clone(),
            r1cs.matrix_b.clone(),
            r1cs.matrix_c.clone(),
        );

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);

        let w_1 = FWitness::new(&witnesses[1], matrix_a.len());
        let mut u_1 = w_1.commit(&scheme, &x[1]);

        // generate trivial_instance
        let (trivial_witness, trivial_instance) =
            create_trivial_pair(x[0].len(), witnesses[0].len(), &scheme);

        // generate f_circuit instance
        let f_circuit = TestCircuit {};

        // generate state
        let z_0 = State {
            state: BaseField::from(0),
        };
        let z_1 = State {
            state: BaseField::from(35),
        };
        let z_2 = State {
            state: BaseField::from(108),
        };
        let mut prover_transcript = Transcript::<Sha256>::default();

        let u_1_x = AugmentedCircuit::<Sha256, TestCircuit>::hash_io(
            BaseField::from(1),
            &z_0,
            &z_1,
            &trivial_instance,
        );
        // convert u_1_x from BaseField into ScalarField
        u_1.x = vec![ScalarField::from_le_bytes_mod_order(
            &u_1_x.into_bigint().to_bytes_le(),
        )];

        let (_, folded_instance, com_t, _) = NIFS::<Sha256>::prover(
            &r1cs,
            &w_1,
            &trivial_witness,
            &u_1,
            &trivial_instance,
            &scheme,
            &mut prover_transcript,
        );

        // create F'
        let mut augmented_circuit = AugmentedCircuit::<Sha256, TestCircuit> {
            f_circuit,
            i: BaseField::from(1),
            trivial_instance: trivial_instance.clone(),
            z_0: z_0.clone(),
            z_i: z_1.clone(),
            z_i1: None,
            h_i: Some(u_1_x),
            h_i1: None,
            phantom_data_t: PhantomData,
        };

        let res1 = augmented_circuit.run(&u_1, Some(&trivial_instance), &w_1, Some(&com_t));

        // check if F' is running
        if res1.is_err() {
            println!("{:?}", res1);
        }

        assert!(res1.is_ok());
        let hash = res1.unwrap();
        // check if the hash output is correct
        assert_eq!(
            hash,
            AugmentedCircuit::<Sha256, TestCircuit>::hash_io(
                BaseField::from(2),
                &z_0,
                &z_2,
                &folded_instance
            )
        );
        augmented_circuit.next_step();
        // check if the state produced is correct
        assert_eq!(augmented_circuit.z_i.state, z_2.state);
    }

    #[test]
    #[should_panic]
    fn test_augmented_circuit_03() {
        // generate R1CS, witnesses and public input, output.
        let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3, 4]);
        let (matrix_a, _, _) = (
            r1cs.matrix_a.clone(),
            r1cs.matrix_b.clone(),
            r1cs.matrix_c.clone(),
        );

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);

        let w_1 = FWitness::new(&witnesses[1], matrix_a.len());
        let mut u_1 = w_1.commit(&scheme, &x[1]);

        // generate trivial_instance
        let (trivial_witness, trivial_instance) =
            create_trivial_pair(x[0].len(), witnesses[0].len(), &scheme);

        // generate f_circuit instance
        let f_circuit = TestCircuit {};

        // generate state
        let z_0 = State {
            state: BaseField::from(0),
        };
        let z_1 = State {
            state: BaseField::from(35),
        };
        let z_2 = State {
            state: BaseField::from(130),
        };
        let mut prover_transcript = Transcript::<Sha256>::default();

        let u_1_x = AugmentedCircuit::<Sha256, TestCircuit>::hash_io(
            BaseField::from(1),
            &z_0,
            &z_1,
            &trivial_instance,
        );
        // convert u_1_x from BaseField into ScalarField
        u_1.x = vec![ScalarField::from_le_bytes_mod_order(
            &u_1_x.into_bigint().to_bytes_le(),
        )];

        let (_, folded_instance, com_t, _) = NIFS::<Sha256>::prover(
            &r1cs,
            &w_1,
            &trivial_witness,
            &u_1,
            &trivial_instance,
            &scheme,
            &mut prover_transcript,
        );

        // create F'
        let mut augmented_circuit = AugmentedCircuit::<Sha256, TestCircuit> {
            f_circuit,
            i: BaseField::from(1),
            trivial_instance: trivial_instance.clone(),
            z_0: z_0.clone(),
            z_i: z_1.clone(),
            z_i1: None,
            h_i: Some(u_1_x),
            h_i1: None,
            phantom_data_t: PhantomData,
        };

        let res1 = augmented_circuit.run(&u_1, Some(&trivial_instance), &w_1, Some(&com_t));

        // check if F' is running
        if res1.is_err() {
            println!("{:?}", res1);
        }

        assert!(res1.is_ok());
        let hash = res1.unwrap();
        // check if the hash output is correct
        assert_eq!(
            hash,
            AugmentedCircuit::<Sha256, TestCircuit>::hash_io(
                BaseField::from(2),
                &z_0,
                &z_2,
                &folded_instance
            )
        );
        augmented_circuit.next_step();
        // check if the state produced is correct
        assert_eq!(augmented_circuit.z_i.state, z_2.state);
    }
}

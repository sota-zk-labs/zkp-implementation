use std::marker::PhantomData;
use std::ops::Add;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use sha2::Digest;
use kzg::commitment::KzgCommitment;
use kzg::types::{BaseField, ScalarField};
use crate::nifs::{NIFS};
use crate::r1cs::{FInstance, FWitness};
use crate::transcript::Transcript;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

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
    pub f_circuit: FC,
    pub i: BaseField,
    pub trivial_instance: FInstance, // trivial instance.
    pub z_0: State,
    pub z_i1: Option<State>, // store the next state, use for update step.
    pub z_i: State,
    pub hash_x: Option<BaseField>,
    pub hash_x_next: Option<BaseField>, // store the next hash IO, use for update step
    pub phantom_data_t: PhantomData<T>,
}

impl <T: Digest + Default + ark_serialize::Write, FC: FCircuit > AugmentedCircuit <T, FC> {

    pub fn new(
        f_circuit: FC,
        trivial_instance: &FInstance,
        z_0: &State,
    ) -> Self {
        Self {
            f_circuit,
            i: BaseField::zero(),
            trivial_instance: trivial_instance.clone(),
            z_0: z_0.clone(),
            z_i: z_0.clone(),
            z_i1: None,
            hash_x: None,
            hash_x_next: None,
            phantom_data_t: PhantomData
        }
    }
    pub fn run(
        &mut self,
        u_i: &FInstance,
        big_u_i: Option<&FInstance>,
        w_i: &FWitness,
        com_t: Option<&KzgCommitment>,
    ) -> Result<BaseField, String>{

        if self.i != BaseField::from(0) {

            // check that if i > 0 then U_i and com_t must exist
            if big_u_i.is_none() || com_t.is_none() {
                return Err(String::from("Wrong parameters."));
            }

            // check that if i > 0 then the hash_x must exist
            if self.hash_x.is_none() {
                return Err(String::from("The hash public IO must exist"))
            }

            // get hash_x
            let hash_x = self.hash_x.clone().unwrap();

            // 1. check that u.x =? hash_x
            // Because u_i.x is in ScalarField while hash_x is in BaseField, they need to
            // be converted into a comparable type
            // Todo: Non-native field transform

            let u_dot_x = u_i.x[0].clone();
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
            let new_hash= Self::hash_io(self.i.add(BaseField::one()), &self.z_0, &z_i1, &big_u_i1);

            // store the next hash
            self.hash_x_next = Some(new_hash);
            // store the next state
            self.z_i1 = Some(z_i1);

        } else { // i == 0

            // compute z_1 = F(z_0, w_i)
            let z_i1 = self.f_circuit.run(&self.z_i, w_i);

            // compute hash
            let new_hash = Self::hash_io(BaseField::one(), &self.z_0, &z_i1, &self.trivial_instance);

            // store the next hash
            self.hash_x_next = Some(new_hash);
            // store the next state
            self.z_i1 = Some(z_i1);
        }

        return Ok(self.hash_x_next.unwrap());
    }

    pub fn next_step(&mut self) {
        self.z_i = self.z_i1.clone().unwrap();
        self.i = self.i + BaseField::one();
        self.hash_x = self.hash_x_next;
    }

    /// A function compute public IO of an instance: u.x = hash(i, z0, zi, Ui).
    pub fn hash_io(
        i: BaseField,
        z_0: &State,
        z_i: &State,
        big_u: &FInstance
    ) -> BaseField {
        let mut hasher = T::default();
        i.serialize_uncompressed(&mut hasher).unwrap();
        z_0.state.serialize_uncompressed(&mut hasher).unwrap();
        z_i.state.serialize_uncompressed(&mut hasher).unwrap();

        big_u.com_e.0.serialize_uncompressed(&mut hasher).unwrap();
        big_u.u.serialize_uncompressed(&mut hasher).unwrap();
        big_u.com_w.0.serialize_uncompressed(&mut hasher).unwrap();

        for x in &big_u.x {
            x.serialize_uncompressed(&mut hasher).unwrap();
        }

        let data = hasher.finalize().to_vec();
        BaseField::from_le_bytes_mod_order(&data)
    }
}


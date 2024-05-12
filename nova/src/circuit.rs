use std::marker::PhantomData;
use std::ops::Add;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, One, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::prelude::StdRng;
use rand::SeedableRng;
use sha2::Digest;
use kzg::commitment::KzgCommitment;
use kzg::types::{BaseField, ScalarField};
use crate::nifs::{NIFS};
use crate::r1cs::{FInstance, FWitness};
use crate::transcript::Transcript;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// State structure of IVC, which is presented in BaseField of Bsn12_381 curve
/// Todo: Implement a general version.
#[derive(Clone)]
pub struct State {
    pub state: BaseField,
}
pub struct FCircuit {
    // state u_i
    u_i: State,
    // state u_{i+1}
    u_i1: State,
}

impl FCircuit {
    pub fn run(&self, fwitness: &FWitness) {

    }
}

/// F' circuit
pub struct AugmentedCircuit<T: Digest + Default + ark_serialize::Write> {
    pub f_circuit: FCircuit,
    pub i: BaseField,
    pub trivial_instance: FInstance, // trivial instance.
    pub z_0: State,
    pub z_i: State,

    phantom_data: PhantomData<T>,
}

impl <T: Digest + Default + ark_serialize::Write> AugmentedCircuit <T>{
    pub fn run(
        &self,
        u_i: &FInstance,
        w_i: &FWitness,
        big_u_i: &FInstance,
        r: Option<ScalarField>,
        com_t: Option<&KzgCommitment>,
        transcript: &mut Transcript<T>,
    ) -> Result<(State, ScalarField), String>{
        // compute hash(i, z_0, z_i, U_i)
        let hash_x = Self::hash_io(self.i, &self.z_0, &self.z_i, big_u_i);

        if self.i != BaseField::from(0) {

            // 1. check that u.x =? hash
            // Because u_i.x is in ScalarField while hash is in BaseField, they need to
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
            if u_i.u.is_one() {
                return Err(String::from("Commitment of E is wrong"));
            }

            // 3. verify challenge r
            let challenge_checker = NIFS::<T>::verify_challenge(r.unwrap(), u_i.u, big_u_i.u, com_t.unwrap(), transcript);
            if challenge_checker.is_err() {
                return Err(challenge_checker.unwrap_err());
            }

            // 3.compute U_{i+1}
            let big_u_i1 = NIFS::<T>::verifier(r.unwrap(), u_i, big_u_i, com_t.unwrap());

            // compute z_{i+1} = F(z_i, w_i)
            self.f_circuit.run(w_i);
            let z_i1 = self.f_circuit.u_i1.clone();

            // compute hash
            let mut new_hash= Self::hash_io(self.i.add(BaseField::one()), &self.z_0, &z_i1, &big_u_i1);
            // convert into ScalarField
            let new_x = ScalarField::from_le_bytes_mod_order(&new_hash.into_bigint().to_bytes_le());
            return Ok((z_i1, new_x));
        } else { // i == 0

            // compute z_1 = F(z_0, w_i)
            self.f_circuit.run(w_i);
            let z_i1 = self.f_circuit.u_i1.clone();
            let new_hash = Self::hash_io(BaseField::one(), &self.z_0, &z_i1, &self.trivial_instance);
            // convert into ScalarField
            let new_x = ScalarField::from_le_bytes_mod_order(&new_hash.into_bigint().to_bytes_le());
            return Ok((z_i1, new_x));
        }

    }

    /// A function compute public IO of an instance: u.x = hash(i, z0, zi, Ui).
    fn hash_io(
        i: BaseField,
        z_i: &State,
        z_i1: &State,
        big_u: &FInstance
    ) -> BaseField {
        let mut hasher = T::default();
        i.serialize_uncompressed(&mut hasher).unwrap();
        z_i.state.serialize_uncompressed(&mut hasher).unwrap();
        z_i1.state.serialize_uncompressed(&mut hasher).unwrap();

        big_u.com_e.0.serialize_uncompressed(&mut hasher).unwrap();
        big_u.u.serialize_uncompressed(&mut hasher).unwrap();
        big_u.com_w.0.serialize_uncompressed(&mut hasher).unwrap();

        for x in &big_u.x {
            x.serialize_uncompressed(&mut hasher).unwrap();
        }

        let data = Some(hasher.finalize().to_vec());
        let mut seed: [u8; 8] = Default::default();
        seed.copy_from_slice(&data.clone().unwrap_or_default()[0..8]);
        let seed = u64::from_le_bytes(seed);
        let mut rng = StdRng::seed_from_u64(seed);
        BaseField::rand(&mut rng)
    }
}


use std::marker::PhantomData;
use std::ops::Add;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, One, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::prelude::StdRng;
use rand::SeedableRng;
use sha2::Digest;
use kzg::types::{BaseField, ScalarField};
use crate::ivc::ZkIVCProof;
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

/// trait for F circuit
pub trait FCircuit<F: PrimeField> {
    // return state z_{i+1} = F(z_i, w_i)
    fn run(&self, z_i: &State, w_i: &FWitness) -> State;
}


/// F' circuit
pub struct AugmentedCircuit<T: Digest + Default + ark_serialize::Write, F: PrimeField,  FC: FCircuit<F>> {
    pub f_circuit: FC,
    pub i: BaseField,
    pub trivial_instance: FInstance, // trivial instance.
    pub z_0: State,
    pub z_i: State,
    phantom_data_t: PhantomData<T>,
    phantom_data_f: PhantomData<F>,
}

impl <T: Digest + Default + ark_serialize::Write, F: PrimeField, FC: FCircuit<F> > AugmentedCircuit <T, F, FC> {
    pub fn run(
        &self,
        zk_ivc_proof: &ZkIVCProof,
        w_i: &FWitness,
        transcript: &mut Transcript<T>,
    ) -> Result<(State, ScalarField), String>{

        let mut z_i1;
        let mut new_x;

        // compute hash(i, z_0, z_i, U_i)
        let hash_x = Self::hash_io(self.i, &self.z_0, &self.z_i, &zk_ivc_proof.big_u_i);

        if self.i != BaseField::from(0) {

            // 1. check that u.x =? hash
            // Because u_i.x is in ScalarField while hash is in BaseField, they need to
            // be converted into a comparable type
            // Todo: Non-native field transform
            let u_dot_x = zk_ivc_proof.u_i.x[0].clone();
            let hash_fr = ScalarField::from_le_bytes_mod_order(&hash_x.into_bigint().to_bytes_le());
            if u_dot_x != hash_fr {
                return Err(String::from("Public IO is wrong "));
            }

            // 2. check that u_i.comE = com_([0,...]) and u_i.u = 1
            if zk_ivc_proof.u_i.com_e != self.trivial_instance.com_e {
                return Err(String::from("Commitment of E is wrong"));
            }
            if zk_ivc_proof.u_i.u.is_one() {
                return Err(String::from("Commitment of E is wrong"));
            }

            // 3. verify challenge r
            let r = zk_ivc_proof.folded_u_proof.clone().unwrap().r;
            let com_t = zk_ivc_proof.com_t.clone().unwrap();

            let challenge_checker = NIFS::<T>::verify_challenge(r, zk_ivc_proof.u_i.u, zk_ivc_proof.big_u_i.u, &com_t, transcript);
            if challenge_checker.is_err() {
                return Err(challenge_checker.unwrap_err());
            }

            // 3.compute U_{i+1}
            let big_u_i1 = NIFS::<T>::verifier(r, &zk_ivc_proof.u_i, &zk_ivc_proof.big_u_i, &com_t);

            // compute z_{i+1} = F(z_i, w_i)
            z_i1 = self.f_circuit.run(&self.z_i, w_i);

            // compute hash
            let mut new_hash= Self::hash_io(self.i.add(BaseField::one()), &self.z_0, &z_i1, &big_u_i1);
            // convert into ScalarField
            new_x = ScalarField::from_le_bytes_mod_order(&new_hash.into_bigint().to_bytes_le());

        } else { // i == 0

            // compute z_1 = F(z_0, w_i)
            z_i1 = self.f_circuit.run(&self.z_i, w_i);

            // compute hash
            let new_hash = Self::hash_io(BaseField::one(), &self.z_0, &z_i1, &self.trivial_instance);
            // convert into ScalarField
            new_x = ScalarField::from_le_bytes_mod_order(&new_hash.into_bigint().to_bytes_le());

        }

        return Ok((z_i1, new_x));

    }
    pub fn next_state(&mut self, z_i1: &State) {
        self.z_i = z_i1.clone();
        self.i = self.i + BaseField::one();
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


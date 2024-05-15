use std::marker::PhantomData;
use std::ops::Mul;
use ark_ec::CurveGroup;

use kzg::commitment::KzgCommitment;
use kzg::types::ScalarField;
use sha2::{Digest};
use kzg::opening::KzgOpening;
use crate::r1cs::{FInstance, FWitness, R1CS};
use crate::utils::{hadamard_product, matrix_vector_product, vec_add, vec_sub, vector_elem_product};

pub(crate) mod nifs_verifier;
mod nifs_prover;

#[derive(Clone)]
pub struct NIFSProof {
    pub r: ScalarField,
    pub opening_point: ScalarField,
    pub opening_e: KzgOpening,
    pub opening_w: KzgOpening
}

pub struct NIFS<T: Digest + Default> {
    _phantom_data_t: PhantomData<T>,
}

impl <T: Digest + Default> NIFS<T> {

    /// Compute the cross-term T
    pub fn compute_t(
        r1cs: &R1CS<ScalarField>,
        u1: ScalarField,
        u2: ScalarField,
        z1: &Vec<ScalarField>,
        z2: &Vec<ScalarField>
    ) -> Vec<ScalarField> {

        let az1 = matrix_vector_product(&r1cs.matrix_a, z1);
        let bz1 = matrix_vector_product(&r1cs.matrix_b, z1);
        let cz1 = matrix_vector_product(&r1cs.matrix_c, z1);
        let az2 = matrix_vector_product(&r1cs.matrix_a, z2);
        let bz2 = matrix_vector_product(&r1cs.matrix_b, z2);
        let cz2 = matrix_vector_product(&r1cs.matrix_c, z2);

        let az1_bz2 = hadamard_product(&az1, &bz2);
        let az2_bz1 = hadamard_product(&az2, &bz1);
        let u1cz2 = vector_elem_product(&cz2, u1);
        let u2cz1 = vector_elem_product(&cz1, u2);

        let mut t = vec_add(&az1_bz2, &az2_bz1);
        t = vec_sub(&t, &u1cz2);
        t = vec_sub(&t, &u2cz1);

        t
    }

    pub fn fold_witness(
        r: ScalarField,
        fw1: &FWitness,
        fw2: &FWitness,
        t: &Vec<ScalarField>,
        // rT: ScalarField,
    ) -> FWitness {

        let new_e = fw1.e.iter().zip(t.iter()).zip(&fw2.e).map(|((e1, t), e2)| {
            *e1 + r * *t + r * r * *e2
        }).collect();

        let new_w = fw1.w.iter().zip(&fw2.w).map(|(a, b)| {
           *a + *b * r
        }).collect();

        FWitness{
            e: new_e,
            w: new_w
        }
    }

    pub fn fold_instance(
        r: ScalarField,
        fi1: &FInstance,
        fi2: &FInstance,
        com_t: &KzgCommitment,
    ) -> FInstance {
        let new_com_e = KzgCommitment((fi1.com_e.0 + com_t.0.mul(r) + fi2.com_e.0.mul(r * r)).into_affine());
        let new_com_w = KzgCommitment((fi1.com_w.0 + fi2.com_w.0.mul(r)).into_affine());

        let new_u = fi1.u + fi2.u * r;
        let new_x = fi1.x.iter().zip(&fi2.x).map(|(a, b)| {
            *a + *b * r
        }).collect();

        FInstance{
            com_e: new_com_e,
            u: new_u,
            com_w: new_com_w,
            x: new_x
        }
    }

}


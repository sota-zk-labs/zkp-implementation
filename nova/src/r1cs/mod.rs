use ark_ff::{PrimeField, Zero, One};
use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;
use kzg::types::ScalarField;
use crate::utils::{hadamard_product, matrix_vector_product, vec_add, vec_equal, vector_elem_product};

/// Create R1CS structure
#[derive(Clone)]
pub struct R1CS<F: PrimeField> {
    pub matrix_a: Vec<Vec<F>>,
    pub matrix_b: Vec<Vec<F>>,
    pub matrix_c: Vec<Vec<F>>,
    pub num_io: usize,
    pub num_vars: usize,
}

/// Create Committed Relaxed R1CS Instance structure with KZG commitment
/// Todo: Need to impl a general-curve commitment.
#[derive(Debug, Clone)]
pub struct FInstance {
    pub com_e: KzgCommitment,
    pub u: ScalarField,
    pub com_w: KzgCommitment,
    pub x: Vec<ScalarField>,
}


/// Create Committed Relaxed FWitness with KZG commitment
/// Todo: Need to implement a general-curve commitment
#[derive(Debug, Clone)]
pub struct FWitness {
    pub e: Vec<ScalarField>,
    // pub rE: ScalarField,
    pub w: Vec<ScalarField>,
    // pub rW: ScalarField,
}

impl FWitness {
    pub fn new(w: &Vec<ScalarField>, len: usize) -> Self {
        FWitness {
            e: vec![ScalarField::zero(); len],
            // rE: ScalarField::rand(&mut rand::thread_rng()),
            w: w.clone(),
            // rW: ScalarField::rand(&mut rand::thread_rng()),
        }
    }

    pub fn new_trivial_witness(len: usize) -> Self {
        FWitness {
            e: vec![ScalarField::zero(); len],
            w: vec![ScalarField::zero(); len],
        }
    }

    pub fn commit(&self, scheme: &KzgScheme, x: &Vec<ScalarField>) -> FInstance {
        let com_e = scheme.commit_vector(&self.e);
        // cE.0 = cE.0.mul(self.rE).into_affine();
        let com_w = scheme.commit_vector(&self.w);
        // cW.0 = cW.0.mul(self.rW).into_affine();

        FInstance {
            com_e: com_e,
            u: ScalarField::one(),
            com_w: com_w,
            x: x.clone(),
        }
    }
}

pub fn is_satis_relaxed(
    r1cs: R1CS<ScalarField>,
    f_instance: FInstance,
    f_witness: FWitness,
    scheme: KzgScheme
) -> Result<(), String> {
    if r1cs.num_vars != f_witness.w.len() {
        return Err(String::from("Witness does not match with matrices"));
    }
    if r1cs.num_io != f_instance.x.len() {
        return Err(String::from("Instance does not match with matrices"));
    }

    // check if: Az * Bz = u*Cz + E
    let mut z = f_witness.w.clone();
    z.append(&mut f_instance.x.clone());
    z.push(f_instance.u);

    let az = matrix_vector_product(&r1cs.matrix_a, &z);
    let bz = matrix_vector_product(&r1cs.matrix_b, &z);
    let cz = matrix_vector_product(&r1cs.matrix_c, &z);

    let left_side = hadamard_product(&az, &bz);
    let ucz = vector_elem_product(&cz, f_instance.u);
    let right_side = vec_add(&ucz, &f_witness.e);

    let res_eq = vec_equal(&left_side, &right_side);

    // check whether Instance satisfies Witness
    let res_com = (f_instance.com_w == scheme.commit_vector(&f_witness.w)) && (f_instance.com_e == scheme.commit_vector(&f_witness.e));

    if res_com && res_eq {
        Ok(())
    } else {
        return Err(String::from("Instance does not satisfy the Witness."))
    }

}


#[cfg(test)]

mod tests {
    use kzg::scheme::KzgScheme;
    use kzg::srs::Srs;
    use kzg::types::ScalarField;
    use crate::nifs::nifs_verifier::gen_test_values;

    #[test]
    pub fn test_r1cs() {
        let (r1cs, witnesses, x) = gen_test_values::<ScalarField>(vec![3, 4]);
        let (matrix_a, _, _) = (r1cs.matrix_a.clone(), r1cs.matrix_b.clone(), r1cs.matrix_c.clone());

        // Trusted setup
        let domain_size = witnesses[0].len() + x[0].len() + 1;
        let srs = Srs::new(domain_size);
        let scheme = KzgScheme::new(srs);


    }
}
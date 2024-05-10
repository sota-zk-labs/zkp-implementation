use ark_ff::PrimeField;

pub fn matrix_vector_product<F: PrimeField>(matrix: &Vec<Vec<F>>, z: &[F]) -> Vec<F> {
    let mut r: Vec<F> = vec![F::zero(); matrix.len()];
    for i in 0..matrix.len() {
        for j in 0..matrix[i].len() {
            r[i] += matrix[i][j] * z[j];
        }
    }
    r
}
pub fn hadamard_product<F: PrimeField>(a: &Vec<F>, b: &Vec<F>) -> Vec<F> {

    let mut r: Vec<F> = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        r[i] = a[i] * b[i];
    }
    r
}

pub fn vector_elem_product<F: PrimeField>(a: &Vec<F>, u: F) -> Vec<F> {
    let mut r: Vec<F> = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        r[i] = a[i] * u;
    }
    r
}

pub fn vec_sub<F: PrimeField>(a: &Vec<F>, b: &Vec<F>) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    let mut r: Vec<F> = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        r[i] = a[i] - b[i];
    }
    r
}

pub fn vec_add<F: PrimeField>(a: &Vec<F>, b: &Vec<F>) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    let mut r: Vec<F> = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        r[i] = a[i] + b[i];
    }
    r
}

pub fn to_f_matrix<F: PrimeField> (matrix: Vec<Vec<usize>>) -> Vec<Vec<F>> {
    let mut r: Vec<Vec<F>> = vec![Vec::new(); matrix.len()];
    for i in 0..matrix.len() {
        r[i] = vec![F::zero(); matrix[i].len()];
        for j in 0..matrix[i].len() {
            r[i][j] = F::from(matrix[i][j] as u64);
        }
    }
    r
}

pub fn to_f_vec<F: PrimeField>(z: Vec<usize>) -> Vec<F> {
    let mut r: Vec<F> = vec![F::zero(); z.len()];
    for i in 0..z.len() {
        r[i] = F::from(z[i] as u64);
    }
    r
}
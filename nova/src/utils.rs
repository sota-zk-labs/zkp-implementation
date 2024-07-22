use ark_ff::PrimeField;

/// Computes the product of a matrix and a vector.
///
/// # Arguments
///
/// * `matrix` - A matrix represented as a vector of vectors.
/// * `z` - A vector to be multiplied by the matrix.
///
/// # Returns
///
/// A vector resulting from the product of the matrix and the vector.
#[allow(dead_code)]
pub fn matrix_vector_product<F: PrimeField>(matrix: &[Vec<F>], z: &[F]) -> Vec<F> {
    let mut r: Vec<F> = vec![F::zero(); matrix.len()];
    for i in 0..matrix.len() {
        for (j, z_j) in z.iter().enumerate().take(matrix[i].len()) {
            r[i] += matrix[i][j] * z_j;
        }
    }
    r
}

/// Computes the Hadamard product of two vectors of equal size.
///
/// # Arguments
///
/// * `a` - The first vector.
/// * `b` - The second vector.
///
/// # Returns
///
/// A vector resulting from the Hadamard product of the two input vectors.
#[allow(dead_code)]
pub fn hadamard_product<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
    let mut r: Vec<F> = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        r[i] = a[i] * b[i];
    }
    r
}

/// Computes the product of an element and a vector.
///
/// # Arguments
///
/// * `a` - The vector.
/// * `u` - The element to be multiplied with the vector.
///
/// # Returns
///
/// A vector resulting from multiplying each element of `a` by `u`.
#[allow(dead_code)]
pub fn vector_elem_product<F: PrimeField>(a: &[F], u: F) -> Vec<F> {
    let mut r: Vec<F> = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        r[i] = a[i] * u;
    }
    r
}

/// Subtracts one vector from another.
///
/// # Arguments
///
/// * `a` - The first vector.
/// * `b` - The second vector.
///
/// # Returns
///
/// A vector resulting from subtracting `b` from `a`.
#[allow(dead_code)]
pub fn vec_sub<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    let mut r: Vec<F> = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        r[i] = a[i] - b[i];
    }
    r
}

/// Adds two vectors.
///
/// # Arguments
///
/// * `a` - The first vector.
/// * `b` - The second vector.
///
/// # Returns
///
/// A vector resulting from adding `a` and `b`.
#[allow(dead_code)]
pub fn vec_add<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    let mut r: Vec<F> = vec![F::zero(); a.len()];
    for i in 0..a.len() {
        r[i] = a[i] + b[i];
    }
    r
}

/// Checks if two vectors are equal.
///
/// # Arguments
///
/// * `a` - The first vector.
/// * `b` - The second vector.
///
/// # Returns
///
/// `true` if `a` and `b` are equal, `false` otherwise.
#[allow(dead_code)]
pub fn vec_equal<F: PrimeField>(a: &[F], b: &[F]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Converts a matrix of `usize` values to a matrix of `F` values.
///
/// # Arguments
///
/// * `matrix` - A matrix represented as a vector of vectors of `usize` values.
///
/// # Returns
///
/// A matrix represented as a vector of vectors of `F` values.
#[allow(dead_code)]
pub fn to_f_matrix<F: PrimeField>(matrix: &[Vec<usize>]) -> Vec<Vec<F>> {
    let mut r: Vec<Vec<F>> = vec![Vec::new(); matrix.len()];
    for i in 0..matrix.len() {
        r[i] = vec![F::zero(); matrix[i].len()];
        for j in 0..matrix[i].len() {
            r[i][j] = F::from(matrix[i][j] as u64);
        }
    }
    r
}

/// Converts a vector of `usize` values to a vector of `F` values.
///
/// # Arguments
///
/// * `z` - A vector of `usize` values.
///
/// # Returns
///
/// A vector of `F` values.
#[allow(dead_code)]
pub fn to_f_vec<F: PrimeField>(z: Vec<usize>) -> Vec<F> {
    let mut r: Vec<F> = vec![F::zero(); z.len()];
    for i in 0..z.len() {
        r[i] = F::from(z[i] as u64);
    }
    r
}

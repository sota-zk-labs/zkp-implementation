use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

/// Computes a cryptographic hash of a single field element using SHA-256.
///
/// # Arguments
///
/// * `data` - A reference to a field element of type `F`.
///
/// # Returns
///
/// * `F` - A field element representing the hash value.
///
pub fn hash<F: PrimeField>(data: &F) -> F {
    let mut hasher = Sha256::new();
    hasher.update(data.to_string());
    let h = hasher.finalize();
    F::from_le_bytes_mod_order(&h)
}

/// Computes a cryptographic hash of a slice of field elements using SHA-256.
///
/// # Arguments
///
/// * `data` - A slice of field elements of type `F`.
///
/// # Returns
///
/// * `F` - A field element representing the hash value.
///
pub fn hash_slice<F: PrimeField>(data: &[F]) -> F {
    let mut hasher = Sha256::new();
    data.iter().for_each(|d| hasher.update(d.to_string()));
    let h = hasher.finalize();
    F::from_le_bytes_mod_order(&h)
}

use ark_ff::{Fp64, MontBackend, MontConfig};
use crate::merkle_tree::FriMerkleTree;
use crate::hasher::Sha256Hasher;

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

#[cfg(test)]
mod tests {
    use ark_ff::AdditiveGroup;
    use crate::hasher::Hasher;
    use super::*;

    #[test]
    fn test_sha256_hasher() {
        let mut hasher = Sha256Hasher::new();
        let value = Fq::from(42u64);
        hasher.digest(&value);
        let result : Fq = hasher.finalize();
        assert_ne!(result, Fq::ZERO); // Basic test to ensure hashing works
    }

    #[test]
    fn test_sha256_hasher_digest_vec() {
        let mut hasher = Sha256Hasher::new();
        let values = vec![Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        hasher.digest_vec(&values);
        let result: Fq = hasher.finalize();
        assert_ne!(result, Fq::ZERO);
    }

    #[test]
    fn test_merkle_tree_construction() {
        let values = vec![
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ];
        let tree = FriMerkleTree::<Fq, Sha256Hasher>::new(values.clone()).unwrap();
        
        // Check that the first level contains the original values
        assert_eq!(tree.nodes[0], values);
        
        // Check that the tree has the correct number of levels
        // For 4 values, we should have 3 levels (original + 2 hashed levels)
        assert_eq!(tree.nodes.len(), 3);
    }

    #[test]
    fn test_merkle_tree_single_value() {
        let values = vec![Fq::from(1u64)];
        let tree = FriMerkleTree::<Fq, Sha256Hasher>::new(values.clone()).unwrap();
        
        // For a single value, we should only have one level
        assert_eq!(tree.nodes.len(), 1);
        assert_eq!(tree.nodes[0], values);
    }

    #[test]
    fn test_merkle_tree_odd_number_of_values() {
        let values = vec![
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
        ];
        let tree = FriMerkleTree::<Fq, Sha256Hasher>::new(values.clone());
        assert!(tree.is_err());
    }
}
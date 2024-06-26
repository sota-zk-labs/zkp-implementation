use ark_ff::PrimeField;

use crate::hasher::{hash, hash_slice};

/// A proof for Merkle tree membership, which includes the leaf index, leaf value, hash proofs, and root.
#[derive(Debug, Clone)]
pub struct MerkleProof<F: PrimeField> {
    /// Index of the leaf the prover wants to reveal.
    pub index: usize,
    /// Value of the leaf the prover wants to reveal.
    pub leaf_val: F,
    /// Hash values of the neighboring nodes.
    hash_proof: Vec<F>,
    /// Root value of the committed Merkle tree.
    root: F,
}

/// A Merkle tree structure that supports the creation of proofs and verification of membership.
#[derive(Debug, Clone)]
pub struct MerkleTree<F: PrimeField> {
    /// The internal nodes of the Merkle tree stored in levels.
    internal_nodes: Vec<Vec<F>>,
    /// Values of the leaf nodes.
    pub leaves: Vec<F>,
    /// Depth of the Merkle tree.
    depth: usize,
}

impl<F: PrimeField> MerkleTree<F> {
    /// Constructs a new Merkle tree from the given evaluations (leaf values).
    ///
    /// # Arguments
    ///
    /// * `evaluations` - A vector of field elements representing the leaf values.
    ///
    /// # Returns
    ///
    /// * `MerkleTree<F>` - A new Merkle tree instance.
    ///
    /// The method hashes the leaf values to create the first level of internal nodes,
    /// and iteratively hashes pairs of nodes to construct the upper levels of the tree.
    pub fn new(mut evaluations: Vec<F>) -> Self {
        let new_len = evaluations.len().next_power_of_two();
        let depth = new_len.ilog2() as usize;

        let first_level = evaluations.iter().map(hash).collect::<Vec<_>>();

        let mut internal_nodes = vec![first_level];

        for i in 0..depth {
            let next_level = internal_nodes[i].chunks(2).map(hash_slice).collect();
            internal_nodes.push(next_level);
        }

        evaluations.resize(new_len, F::ZERO); // Fill the rest of the tree with 0

        Self {
            internal_nodes,
            leaves: evaluations,
            depth,
        }
    }

    /// Retrieves the root of the Merkle tree.
    ///
    /// # Returns
    ///
    /// * `F` - The root hash of the Merkle tree.
    pub fn root(&self) -> F {
        self.internal_nodes.last().unwrap()[0]
    }

    /// Generates a Merkle proof for a leaf at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the leaf for which to generate the proof.
    ///
    /// # Returns
    ///
    /// * `MerkleProof<F>` - A proof containing the leaf index, leaf value, hash proofs, and root.
    pub fn generate_proof(&self, index: usize) -> MerkleProof<F> {
        let leaf_val = self.leaves[index];
        let mut hash_proof = Vec::with_capacity(self.depth);
        let mut cur_index = index;
        for i in 0..self.depth {
            let neighbour = if cur_index % 2 == 0 {
                // The current node is a left node, we need the right node.
                self.internal_nodes[i][cur_index + 1]
            } else {
                self.internal_nodes[i][cur_index - 1]
            };
            hash_proof.push(neighbour);
            cur_index /= 2;
        }

        MerkleProof {
            index,
            leaf_val,
            hash_proof,
            root: self.root(),
        }
    }
}

/// Verifies a Merkle proof against the root of the Merkle tree.
///
/// # Arguments
///
/// * `proof` - A reference to a MerkleProof instance.
///
/// # Returns
///
/// * `bool` - `true` if the proof is valid, `false` otherwise.
///
/// The function reconstructs the hash path from the leaf node to the root and checks if it matches the given root.
pub fn verify_merkle_proof<F: PrimeField>(proof: &MerkleProof<F>) -> bool {
    let mut cur_index = proof.index;
    let mut cur_hash = hash(&proof.leaf_val);
    for i in 0..proof.hash_proof.len() {
        if cur_index % 2 == 0 {
            // The current node is a left node
            let neighbour = proof.hash_proof[i];
            cur_hash = hash_slice(&[cur_hash, neighbour]);
        } else {
            let neighbour = proof.hash_proof[i];
            cur_hash = hash_slice(&[neighbour, cur_hash]);
        }
        cur_index /= 2;
    }
    cur_hash == proof.root
}

#[cfg(test)]
mod tests {
    use crate::fields::goldilocks::Fq;

    use super::*;

    #[test]
    fn test_merkle() {
        let leaves = vec![1, 2, 3, 4];
        let new_leaves: Vec<Fq> = leaves.into_iter().map(Fq::from).collect();
        let tree = MerkleTree::new(new_leaves);

        let merkle_proof = tree.generate_proof(1);
        // merkle_proof.index = 2;
        let verify = verify_merkle_proof(&merkle_proof);

        assert_eq!(verify, true);
    }
}

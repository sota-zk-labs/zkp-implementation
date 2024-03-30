use ark_ff::PrimeField;
use crate::hasher::CustomizedHash;
#[derive(Debug)]
pub struct MerkleProof<F: PrimeField> {
    pub index: usize,
    pub leaf_val: F,
    hash_proof: Vec<F>,
    merkle_root: F,
}
pub struct MerkleTree<F: PrimeField> {
    pub root: F,
    levels: Vec<Vec<F>>, // the hash of internal nodes
    pub leaves: Vec<F>, // value of leaves nodes.
    depth: usize,
}

impl<F: PrimeField > MerkleTree<F> {
    pub fn new(evaluations: &Vec<F>) -> Self {
        let mut leaves = evaluations.clone();
        let new_len = evaluations.len().next_power_of_two();
        leaves.resize(new_len, F::ZERO);
        let depth = (new_len as f64).log2() as usize;

        let mut levels: Vec<Vec<F>> = Vec::new();

        let first_level = evaluations.iter().map(|v| CustomizedHash::<F>::hash_one(v.clone())).collect();
        levels.push(first_level);

        for i in 0..depth {
            let current_layer = levels[i].clone();
            let next_layer = current_layer.chunks(2).map(|nodes|
                CustomizedHash::<F>::hash_two(nodes[0], nodes[1])).collect();
            levels.push(next_layer);
        }

        let merkle_root = levels[depth][0].clone();

        Self {
            root: merkle_root,
            levels: levels,
            leaves: leaves,
            depth: depth
        }
    }

    pub fn generate_proof(&self, index: usize) -> MerkleProof<F> {
        let leaf_val = self.leaves[index].clone();
        let mut hash_proof = Vec::new();
        let last_level = self.depth;
        let mut cur_index = index.clone();
        for i in 0..last_level {
            if cur_index % 2 == 0 {
                // current node is on the left, we need the right node.
                let neighbour = self.levels[i][cur_index + 1];
                hash_proof.push(neighbour);
                cur_index /= 2;
            } else {
                let neighbour = self.levels[i][cur_index - 1];
                hash_proof.push(neighbour);
                cur_index /= 2;
            }
        }

        MerkleProof {
            index,
            leaf_val,
            hash_proof,
            merkle_root: self.root
        }
    }
}

pub fn verify_merkle_proof<F: PrimeField, >(proof: &MerkleProof<F>) -> bool {
    let mut cur_index = proof.index;
    let mut cur_hash = CustomizedHash::<F>::hash_one(proof.leaf_val);
    for i in 0..proof.hash_proof.len() {
        if cur_index % 2 == 0 {
            // current node is a left node
            let neighbour = proof.hash_proof[i];
            cur_hash = CustomizedHash::<F>::hash_two(cur_hash, neighbour);
            cur_index /= 2;
        } else {
            let neighbour = proof.hash_proof[i];
            cur_hash = CustomizedHash::<F>::hash_two(neighbour, cur_hash);
            cur_index /= 2;
        }
    }
    return (cur_hash == proof.merkle_root);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fields::goldilocks::Fq};
    #[test]
    fn test_merkle() {
        let leaves = vec![1, 2, 3, 4];
        let new_leaves:Vec<Fq> = leaves.iter().map(|x| Fq::from(x.clone())).collect();
        let mut tree = MerkleTree::<Fq>::new(&new_leaves);

        let root = tree.root;

        println!("root {:?}", root);

        let mut merkle_proof = tree.generate_proof(1);
        println!("{:?}", merkle_proof);
        // merkle_proof.index = 2;

        let verify = verify_merkle_proof(&merkle_proof);
        println!("verify : {:?}", verify);

        assert_eq!(verify, true);
    }
}
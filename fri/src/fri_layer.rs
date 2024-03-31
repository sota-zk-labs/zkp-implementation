use ark_ff::{PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_poly::univariate::DensePolynomial;
use crate::merkle_tree::MerkleTree;
#[derive(Clone)]
pub struct FriLayer<F: PrimeField> {
    pub evaluations: Vec<F>,
    pub merkle_tree: MerkleTree<F>,
    pub coset: F,
    pub domain_size: usize
}

impl <F: PrimeField> FriLayer<F> {
    pub fn new(
        poly: &DensePolynomial<F>,
        coset: &F,
        domain_size: usize
    ) -> Self {
        let domain = <GeneralEvaluationDomain<F>>::new(domain_size).unwrap();

        let evaluations = domain.elements().map(|root| {
            let cur1 = root * coset;
            poly.evaluate(&cur1)
        }).collect::<Vec<_>>();

        let merkle_tree = MerkleTree::new(&evaluations);


        Self {
            evaluations,
            merkle_tree,
            coset: coset.clone(),
            domain_size
        }
    }
}
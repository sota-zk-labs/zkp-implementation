use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};

use crate::merkle_tree::MerkleTree;

/// Represents the state of FRI variables in each interaction.
#[derive(Clone)]
pub struct FriLayer<F: PrimeField> {
    /// Values of the committed polynomial evaluated at a subset Omega of the field F.
    pub evaluations: Vec<F>,
    /// Merkle tree constructed from the evaluated values of the committed polynomial at a subset Omega of F.
    pub merkle_tree: MerkleTree<F>,
    /// Coset value used for polynomial evaluation.
    pub coset: F,
    /// Size of the domain subset Omega.
    pub domain_size: usize,
}

impl<F: PrimeField> FriLayer<F> {
    /// Constructs a new FRI layer from a given dense polynomial, coset value, and domain size.
    ///
    /// # Arguments
    ///
    /// * `poly` - A reference to a dense polynomial to be evaluated.
    /// * `coset` - The coset value to be used in the evaluation of the polynomial.
    /// * `domain_size` - The size of the domain subset Omega.
    ///
    /// # Returns
    ///
    /// * `FriLayer` - A new instance of `FriLayer` containing the evaluations and Merkle tree.
    ///
    /// # Panics
    ///
    /// This function will panic if the domain cannot be created with the given domain size.
    pub fn from_poly(poly: &DensePolynomial<F>, coset: F, domain_size: usize) -> Self {
        // Create a domain for polynomial evaluation.
        let domain = <GeneralEvaluationDomain<F>>::new(domain_size).unwrap();
        // Evaluate the polynomial at each point in the domain.
        let evaluations = domain
            .elements()
            .map(|root| {
                let cur1 = root * coset; // Multiply root by coset.
                poly.evaluate(&cur1) // Evaluate polynomial at the modified root.
            })
            .collect::<Vec<_>>();
        // Create a Merkle tree from the evaluations.
        let merkle_tree = MerkleTree::new(evaluations.clone());

        Self {
            evaluations,
            merkle_tree,
            coset,
            domain_size,
        }
    }
}

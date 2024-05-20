use ark_ff::PrimeField;

use crate::pcs::base_pcs::BasePCS;
use crate::types::Poly;

/// This struct represents the proof in Plookup protocol
pub struct PlookupProof<F: PrimeField, P: BasePCS<F>> {
    /// The proof that can be integrated with arbitrary PCS proof.
    pub base_proof: PlookupBaseProof<F, P>,
    /// The proof depending on PCS.
    pub pcs_proof: P::LookupProof,
}

/// The base proof.
pub struct PlookupBaseProof<F: PrimeField, P: BasePCS<F>> {
    /// Size of the table.
    pub d: usize,
    /// All necessary evaluations
    pub evaluations: PlookupEvaluations<F>,
    /// All necessary commitments
    pub commitments: PlookupCommitments<P::Commitment>,
}

/// Necessary evaluations of base proof.
pub struct PlookupEvaluations<F: PrimeField> {
    /// `f(x)`.
    pub f: F,
    /// `t(x)`.
    pub t: F,
    /// `t(gx)`.
    pub t_g: F,
    /// `h1(x)`.
    pub h1: F,
    /// `h1(gx)`.
    pub h1_g: F,
    /// `h2(x)`.
    pub h2: F,
    /// `h2(gx)`.
    pub h2_g: F,
    /// `z(x)`.
    pub z: F,
    /// `z(gx)`.
    pub z_g: F,
}

/// Necessary commitments of base proof.
pub struct PlookupCommitments<Commitment> {
    /// `com(f_i)`, `i = 1...w` where `w` is the length of an element in table.
    pub f_i: Vec<Commitment>,
    /// `com(t_i)`, `i = 1...w`.
    pub t_i: Vec<Commitment>,
    /// `com(q)`.
    pub q: Commitment,
    /// `com(h1)`.
    pub h1: Commitment,
    /// `com(h2)`.
    pub h2: Commitment,
    /// `com(z)`.
    pub z: Commitment,
}

/// The proof data to forward to PCS, more details in [`prove`](crate::plookup::scheme::Plookup::prove) function
pub struct PlookupProveTransferData<F: PrimeField> {
    pub f_poly: Poly<F>,
    pub t_poly: Poly<F>,
    pub h1_poly: Poly<F>,
    pub h2_poly: Poly<F>,
    pub z_poly: Poly<F>,
    pub quotient_poly: Poly<F>,
    pub evaluation_challenge: F,
    pub shifted_evaluation_challenge: F,
}
/// The verification data to forward to PCS, more details in [`verify`](crate::plookup::scheme::Plookup::verify) function
pub struct PlookupVerifyTransferData<F: PrimeField, Commitment> {
    pub f_commit: Commitment,
    pub t_commit: Commitment,
    pub quotient_eval: F,
    pub evaluation_challenge: F,
    pub shifted_evaluation_challenge: F,
}

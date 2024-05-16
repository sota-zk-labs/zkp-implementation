use std::ops::{Add, Mul};

use ark_ff::PrimeField;

use crate::errors::Error;
use crate::transcript::{ToBytes, TranscriptProtocol};
use crate::types::{LookupProof, LookupProofTransferData, LookupVerifyTransferData, Poly};

/// This trait represents the base polynomial commitment scheme (PCS).
/// Other PCS traits should inherit this trait.
///
/// > [!NOTE]
/// >
/// > Functions `lookup_prove` and `lookup_verify` are implemented based on the idea that the lookup
/// > scheme will generate common data, then the rest of the `prove` and `verify` functions in lookup scheme
/// > will be completed depending on the PCS.
pub trait BasePCS<F: PrimeField>: Sized {
    /// The type of commitment.
    type Commitment: ToBytes
        + Clone
        + Add<Output = Self::Commitment>
        + Mul<F, Output = Self::Commitment>;
    /// The type of opening data.
    type Opening;
    /// The type of proof for verifying the correctness of an opening.
    type Proof;
    /// The type of extra data that PCS need to verify a lookup proof.
    type LookupProof;

    /// Commits to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `poly`: The polynomial to be committed to.
    ///
    /// returns: `Self::Commitment` as the commitment
    fn commit(&self, poly: &Poly<F>) -> Self::Commitment;
    /// Opens a commitment at a specified point.
    ///
    /// # Arguments
    ///
    /// * `poly`: The polynomial to be opened.
    /// * `z`: The point at which the polynomial is opened.
    ///
    /// returns: `Self::Opening` as the opening at the specified point.
    fn open(&self, poly: &Poly<F>, z: F) -> Self::Opening;
    /// Verifies a proof of PCS.
    ///
    /// # Arguments
    ///
    /// * `proof`: The proof to be verified.
    ///
    /// returns: `true` if the proof is valid, otherwise `false`.
    fn verify(&self, proof: &Self::Proof) -> bool;
    /// Generates a PCS proof for lookup scheme.
    ///
    /// # Arguments
    ///
    /// * `transcript`: The transcript generator.
    /// * `data`: The forwarded data from function `prove` of lookup scheme.
    ///
    /// returns: `Ok(Self::LookupProof)` if the proof is successfully generated, otherwise returns an `Error`.
    fn lookup_prove(
        &self,
        transcript: &mut TranscriptProtocol<F>,
        data: &LookupProofTransferData<F>,
    ) -> Result<Self::LookupProof, Error>;
    /// Verifies a lookup PCS proof.
    ///
    /// # Arguments
    ///
    /// * `transcript`: The transcript generator.
    /// * `proof`: The proof needs to be verified.
    /// * `data`: The forwarded data from function `verify` of lookup scheme.
    ///
    /// returns: `Ok(true)` if the proof is valid, `Ok(false)` if invalid, otherwise returns an `Error`.
    fn lookup_verify(
        &self,
        transcript: &mut TranscriptProtocol<F>,
        proof: &LookupProof<F, Self>,
        data: &LookupVerifyTransferData<F, Self::Commitment>,
    ) -> Result<bool, Error>;
}

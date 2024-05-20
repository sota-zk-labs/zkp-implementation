use ark_ff::PrimeField;

use crate::errors::Error;
use crate::pcs::base_pcs::BasePCS;
use crate::transcript::TranscriptProtocol;

/// This trait defines the basic methods of a lookup scheme.
pub trait Lookup<F: PrimeField, P: BasePCS<F>> {
    /// The type representing the proof of the lookup table.
    type Proof;
    /// The type representing the elements stored in the lookup table.
    type Element;

    /// Generates a proof of the lookup table.
    ///
    /// # Arguments
    ///
    /// * `transcript`: The transcript generator.
    ///
    /// returns: The proof of the lookup table.
    fn prove(&self, transcript: &mut TranscriptProtocol<F>) -> Self::Proof;

    /// Verifies a proof of the lookup table.
    ///
    /// # Arguments
    ///
    /// * `transcript`: The transcript generator.
    /// * `proof`: The proof of the lookup table.
    ///
    /// returns: Returns `true` if the proof is valid, otherwise `false`.
    fn verify(
        &self,
        transcript: &mut TranscriptProtocol<F>,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;

    /// Adds a witness that needs to be proven to exist in the table
    ///
    /// # Arguments
    ///
    /// * `witness`: The witness.
    ///
    /// returns: Returns `Ok(())` if the witness is successfully added, otherwise returns an `Error`.
    fn add_witness(&mut self, witness: Self::Element) -> Result<(), Error>;
}

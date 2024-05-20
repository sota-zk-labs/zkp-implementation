use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;

use crate::errors::Error;
use crate::pcs::additive_homomorphic::AdditiveHomomorphicPCS;
use crate::pcs::base_pcs::BasePCS;
use crate::plookup::transcript_label::TranscriptLabel;
use crate::poly::ExtraDensePoly;
use crate::transcript::{ToBytes, TranscriptProtocol};
use crate::types::{LookupProof, LookupProofTransferData, LookupVerifyTransferData, Poly};
use kzg::commitment::KzgCommitment;
use kzg::opening::KzgOpening as OtherKzgOpening;
use kzg::scheme::KzgScheme;

impl ToBytes for KzgCommitment {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.inner().serialize_uncompressed(&mut bytes).expect("");
        bytes
    }
}
pub type KzgField = Fr;

/// This struct represents extra proof that used to verify in `Plookup` using KZG
pub struct PlookupKZGProof<Commitment> {
    /// Commitment of aggregated quotient polynomial that evaluated at `evaluation_challenge`
    pub agg_quotient_commitment: Commitment,
    /// Commitment of aggregated quotient polynomial that evaluated at `evaluation_challenge * g`
    pub shifted_agg_quotient_commitment: Commitment,
}

/// The KZG proof
pub struct KzgProof<F: PrimeField, Commitment> {
    f_com: Commitment,
    opening: KzgOpening<F, Commitment>,
    z: F,
}

/// The KZG opening
pub struct KzgOpening<F: PrimeField, Commitment> {
    q_com: Commitment,
    fz: F,
}

/// Implements KZG to deal with `Plookup`
impl BasePCS<KzgField> for KzgScheme {
    type Commitment = KzgCommitment;
    type Opening = KzgOpening<KzgField, Self::Commitment>;
    type Proof = KzgProof<KzgField, Self::Commitment>;
    type LookupProof = PlookupKZGProof<KzgCommitment>;

    fn commit(&self, poly: &Poly<KzgField>) -> KzgCommitment {
        self.commit(poly)
    }

    fn open(&self, poly: &Poly<KzgField>, z: KzgField) -> Self::Opening {
        let c = self.open(poly.clone(), z);
        KzgOpening {
            q_com: KzgCommitment(c.0),
            fz: c.1,
        }
    }

    fn verify(&self, proof: &Self::Proof) -> bool {
        self.verify(
            &proof.f_com,
            &OtherKzgOpening(proof.opening.q_com.0, proof.opening.fz),
            proof.z,
        )
    }

    #[allow(irrefutable_let_patterns)]
    fn lookup_prove(
        &self,
        transcript: &mut TranscriptProtocol<KzgField>,
        data: &LookupProofTransferData<KzgField>,
    ) -> Result<PlookupKZGProof<KzgCommitment>, Error> {
        if let LookupProofTransferData::Plookup(data) = data {
            let aggregation_challenge =
                transcript.challenge_scalar(TranscriptLabel::WITNESS_AGGREGATION);

            // Calculates the aggregated quotient polynomials for all polynomials that evaluated at `evaluation_challenge`
            let agg_quotient_witness_poly = Self::aggregate_polys(
                &vec![
                    &data.f_poly,
                    &data.t_poly,
                    &data.h1_poly,
                    &data.h2_poly,
                    &data.z_poly,
                    &data.quotient_poly,
                ],
                &aggregation_challenge,
            )
            .unwrap()
            .quotient_poly(&data.evaluation_challenge);
            let agg_quotient_witness_commit = self.commit(&agg_quotient_witness_poly);

            // Calculates the aggregated quotient polynomials for all polynomials that evaluated at `evaluation_challenge * g`
            let shifted_agg_quotient_witness_poly = Self::aggregate_polys(
                &vec![&data.t_poly, &data.h1_poly, &data.h2_poly, &data.z_poly],
                &aggregation_challenge,
            )
            .unwrap()
            .quotient_poly(&data.shifted_evaluation_challenge);
            let shifted_agg_quotient_witness_commit =
                self.commit(&shifted_agg_quotient_witness_poly);

            return Ok(Self::LookupProof {
                agg_quotient_commitment: agg_quotient_witness_commit,
                shifted_agg_quotient_commitment: shifted_agg_quotient_witness_commit,
            });
        }
        Err(Error::WrongLookupScheme)
    }

    #[allow(irrefutable_let_patterns)]
    fn lookup_verify(
        &self,
        transcript: &mut TranscriptProtocol<KzgField>,
        proof: &LookupProof<KzgField, Self>,
        data: &LookupVerifyTransferData<KzgField, Self::Commitment>,
    ) -> Result<bool, Error> {
        if let LookupProof::Plookup(p_proof) = proof {
            if let LookupVerifyTransferData::Plookup(p_data) = data {
                let aggregation_challenge =
                    transcript.challenge_scalar(TranscriptLabel::WITNESS_AGGREGATION);
                let agg_witness_commit = Self::aggregate(
                    &vec![
                        &p_data.f_commit,
                        &p_data.t_commit,
                        &p_proof.base_proof.commitments.h1,
                        &p_proof.base_proof.commitments.h2,
                        &p_proof.base_proof.commitments.z,
                        &p_proof.base_proof.commitments.q,
                    ],
                    &aggregation_challenge,
                )
                .unwrap();
                let agg_witness_eval = Self::aggregate(
                    &vec![
                        &p_proof.base_proof.evaluations.f,
                        &p_proof.base_proof.evaluations.t,
                        &p_proof.base_proof.evaluations.h1,
                        &p_proof.base_proof.evaluations.h2,
                        &p_proof.base_proof.evaluations.z,
                        &p_data.quotient_eval,
                    ],
                    &aggregation_challenge,
                )
                .unwrap();
                let shifted_agg_witness_commit = Self::aggregate(
                    &vec![
                        &p_data.t_commit,
                        &p_proof.base_proof.commitments.h1,
                        &p_proof.base_proof.commitments.h2,
                        &p_proof.base_proof.commitments.z,
                    ],
                    &aggregation_challenge,
                )
                .unwrap();
                let shifted_agg_witness_eval = Self::aggregate(
                    &vec![
                        &p_proof.base_proof.evaluations.t_g,
                        &p_proof.base_proof.evaluations.h1_g,
                        &p_proof.base_proof.evaluations.h2_g,
                        &p_proof.base_proof.evaluations.z_g,
                    ],
                    &aggregation_challenge,
                )
                .unwrap();
                return Ok(self.batch_verify(
                    &[agg_witness_commit, shifted_agg_witness_commit],
                    &[
                        p_data.evaluation_challenge,
                        p_data.shifted_evaluation_challenge,
                    ],
                    &[
                        OtherKzgOpening(
                            p_proof.pcs_proof.agg_quotient_commitment.clone().0,
                            agg_witness_eval,
                        ),
                        OtherKzgOpening(
                            p_proof.pcs_proof.shifted_agg_quotient_commitment.clone().0,
                            shifted_agg_witness_eval,
                        ),
                    ],
                    &mut test_rng(),
                ));
            }
        }
        Err(Error::WrongLookupScheme)
    }
}

impl AdditiveHomomorphicPCS<KzgField> for KzgScheme {}

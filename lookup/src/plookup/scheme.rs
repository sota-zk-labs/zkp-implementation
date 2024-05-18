use std::collections::HashSet;
use std::ops::{Add, Mul};

use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Polynomial};

use crate::errors::Error;
use crate::lookup::Lookup;
use crate::multiset::Multiset;
use crate::pcs::additive_homomorphic::AdditiveHomomorphicPCS;
use crate::pcs::kzg10::KZG12_381;
use crate::plookup::quotient_poly::QuotientPoly;
use crate::plookup::transcript_label::TranscriptLabel;
use crate::plookup::types::{
    PlookupBaseProof, PlookupCommitments, PlookupEvaluations, PlookupProof,
    PlookupProveTransferData, PlookupVerifyTransferData,
};
use crate::poly::ExtraDensePoly;
use crate::transcript::{TranscriptProtocol};
use crate::types::{Domain, LookupProof, LookupProofTransferData, LookupVerifyTransferData, Poly};

pub struct Plookup<F: PrimeField, P: AdditiveHomomorphicPCS<F> = KZG12_381>
    where P::Commitment: Add<Output=P::Commitment>
    + Mul<F, Output=P::Commitment> {
    /// The length of an element
    w: usize,
    /// The witnesses
    f: Vec<Multiset<F>>,
    /// The table
    t: Vec<Multiset<F>>,
    /// The hash table of elements in the table
    hash_t: HashSet<Vec<F>>,
    /// The PCS
    pcs: P,
}

#[allow(clippy::type_complexity)]
impl<F: PrimeField, P: AdditiveHomomorphicPCS<F>> Lookup<F, P> for Plookup<F, P>
    where P::Commitment: Add<Output=P::Commitment>
    + Mul<F, Output=P::Commitment> {
    type Proof = PlookupProof<F, P>;
    type Element = Multiset<F>;

    fn prove(&self, transcript: &mut TranscriptProtocol<F>) -> Self::Proof {
        let (fold_f, f_i_commit, fold_t, t_i_commit) = self.preprocess(transcript);
        let domain: Domain<F> = EvaluationDomain::<F>::new(fold_t.0.len()).unwrap();

        // Computes f,t,h1,h2 and send their commitments to verifier
        let f_poly = Poly::from_evaluations(&fold_f.0, &domain);
        let f_commit = self.pcs.commit(&f_poly);
        let t_poly = Poly::from_evaluations(&fold_t.0, &domain);
        let t_commit = self.pcs.commit(&t_poly);
        let (h1, h2) = Self::compute_h1_h2(&fold_f, &fold_t).unwrap();
        let h1_poly = Poly::from_evaluations(&h1.0, &domain);
        let h2_poly = Poly::from_evaluations(&h2.0, &domain);
        let h1_commit = self.pcs.commit(&h1_poly);
        let h2_commit = self.pcs.commit(&h2_poly);
        transcript.append_commitment(TranscriptLabel::F_COMMIT, &f_commit);
        transcript.append_commitment(TranscriptLabel::T_COMMIT, &t_commit);
        transcript.append_commitment(TranscriptLabel::H1_COMMIT, &h1_commit);
        transcript.append_commitment(TranscriptLabel::H2_COMMIT, &h2_commit);

        // Verifier sends random beta, gamma
        let beta = transcript.challenge_scalar(TranscriptLabel::BETA);
        let gamma = transcript.challenge_scalar(TranscriptLabel::GAMMA);

        // Computes z polynomial and send its commitment to verifier
        let z_poly =
            Self::compute_accumulator_poly(&fold_f, &fold_t, &h1, &h2, &beta, &gamma, &domain);
        let z_commit = self.pcs.commit(&z_poly);
        transcript.append_commitment(TranscriptLabel::Z_COMMIT, &z_commit);

        // Computes quotient polynomial and send its commitment to verifier
        let quotient_poly = QuotientPoly::compute_quotient_poly(
            &f_poly, &t_poly, &h1_poly, &h2_poly, &z_poly, &domain, beta, gamma,
        );
        let quotient_commit = self.pcs.commit(&quotient_poly);
        transcript.append_commitment(TranscriptLabel::Q_COMMIT, &quotient_commit);

        // Verifier sends evaluation challenge
        let evaluation_challenge = transcript.challenge_scalar(TranscriptLabel::OPENING);
        let shifted_evaluation_challenge = evaluation_challenge * domain.group_gen();

        // Computes evaluations at `challenge`
        let f_eval = f_poly.evaluate(&evaluation_challenge);
        let t_eval = t_poly.evaluate(&evaluation_challenge);
        let h1_eval = h1_poly.evaluate(&evaluation_challenge);
        let h2_eval = h2_poly.evaluate(&evaluation_challenge);
        let z_eval = z_poly.evaluate(&evaluation_challenge);
        let q_eval = quotient_poly.evaluate(&evaluation_challenge);

        // Computes evaluations at `challenge * g`
        let t_g_eval = t_poly.evaluate(&shifted_evaluation_challenge);
        let h1_g_eval = h1_poly.evaluate(&shifted_evaluation_challenge);
        let h2_g_eval = h2_poly.evaluate(&shifted_evaluation_challenge);
        let z_g_eval = z_poly.evaluate(&shifted_evaluation_challenge);

        // Sends evaluations to verifier
        transcript.append_scalar(TranscriptLabel::F_EVAL, &f_eval);
        transcript.append_scalar(TranscriptLabel::T_EVAL, &t_eval);
        transcript.append_scalar(TranscriptLabel::H1_EVAL, &h1_eval);
        transcript.append_scalar(TranscriptLabel::H2_EVAL, &h2_eval);
        transcript.append_scalar(TranscriptLabel::Z_EVAL, &z_eval);
        transcript.append_scalar(TranscriptLabel::Q_EVAL, &q_eval);
        transcript.append_scalar(TranscriptLabel::T_G_EVAL, &t_g_eval);
        transcript.append_scalar(TranscriptLabel::H1_G_EVAL, &h1_g_eval);
        transcript.append_scalar(TranscriptLabel::H2_G_EVAL, &h2_g_eval);
        transcript.append_scalar(TranscriptLabel::Z_G_EVAL, &z_g_eval);

        let base_proof = PlookupBaseProof {
            d: fold_t.0.len(),
            evaluations: PlookupEvaluations {
                f: f_eval,
                t: t_eval,
                t_g: t_g_eval,
                h1: h1_eval,
                h1_g: h1_g_eval,
                h2: h2_eval,
                h2_g: h2_g_eval,
                z: z_eval,
                z_g: z_g_eval,
            },
            commitments: PlookupCommitments {
                f_i: f_i_commit,
                t_i: t_i_commit,
                q: quotient_commit,
                h1: h1_commit,
                h2: h2_commit,
                z: z_commit,
            },
        };

        Self::Proof {
            base_proof,
            pcs_proof: self
                .pcs
                .lookup_prove(
                    transcript,
                    &LookupProofTransferData::Plookup(PlookupProveTransferData {
                        f_poly,
                        t_poly,
                        h1_poly,
                        h2_poly,
                        z_poly,
                        quotient_poly,
                        evaluation_challenge,
                        shifted_evaluation_challenge,
                    }),
                )
                .unwrap(),
        }
    }

    fn verify(&self, transcript: &mut TranscriptProtocol<F>, proof: &Self::Proof) -> bool {
        let domain = Domain::<F>::new(proof.base_proof.d).unwrap();
        // Appends `com(f_i)`
        for fi_commit in &proof.base_proof.commitments.f_i {
            transcript.append_commitment(TranscriptLabel::F_I_COMMIT, fi_commit);
        }
        let zeta = transcript.challenge_scalar(TranscriptLabel::ZETA);
        let f_commit =
            P::aggregate(&proof.base_proof.commitments.f_i.iter().collect(), &zeta).unwrap();
        let t_commit =
            P::aggregate(&proof.base_proof.commitments.t_i.iter().collect(), &zeta).unwrap();
        transcript.append_commitment(TranscriptLabel::F_COMMIT, &f_commit);
        transcript.append_commitment(TranscriptLabel::T_COMMIT, &t_commit);
        transcript.append_commitment(TranscriptLabel::H1_COMMIT, &proof.base_proof.commitments.h1);
        transcript.append_commitment(TranscriptLabel::H2_COMMIT, &proof.base_proof.commitments.h2);

        let beta = transcript.challenge_scalar(TranscriptLabel::BETA);
        let gamma = transcript.challenge_scalar(TranscriptLabel::GAMMA);

        transcript.append_commitment(TranscriptLabel::Z_COMMIT, &proof.base_proof.commitments.z);
        transcript.append_commitment(TranscriptLabel::Q_COMMIT, &proof.base_proof.commitments.q);

        let evaluation_challenge = transcript.challenge_scalar(TranscriptLabel::OPENING);
        let shifted_evaluation_challenge = evaluation_challenge * domain.group_gen();
        // Computes quotient evaluation from the prover's messages
        let quotient_eval = QuotientPoly::compute_quotient_evaluation(
            &proof.base_proof.evaluations,
            &beta,
            &gamma,
            &evaluation_challenge,
            &domain,
        );

        transcript.append_scalar(TranscriptLabel::F_EVAL, &proof.base_proof.evaluations.f);
        transcript.append_scalar(TranscriptLabel::T_EVAL, &proof.base_proof.evaluations.t);
        transcript.append_scalar(TranscriptLabel::H1_EVAL, &proof.base_proof.evaluations.h1);
        transcript.append_scalar(TranscriptLabel::H2_EVAL, &proof.base_proof.evaluations.h2);
        transcript.append_scalar(TranscriptLabel::Z_EVAL, &proof.base_proof.evaluations.z);
        transcript.append_scalar(TranscriptLabel::Q_EVAL, &quotient_eval);
        transcript.append_scalar(TranscriptLabel::T_G_EVAL, &proof.base_proof.evaluations.t_g);
        transcript.append_scalar(
            TranscriptLabel::H1_G_EVAL,
            &proof.base_proof.evaluations.h1_g,
        );
        transcript.append_scalar(
            TranscriptLabel::H2_G_EVAL,
            &proof.base_proof.evaluations.h2_g,
        );
        transcript.append_scalar(TranscriptLabel::Z_G_EVAL, &proof.base_proof.evaluations.z_g);

        self.pcs
            .lookup_verify(
                transcript,
                &LookupProof::Plookup(proof),
                &LookupVerifyTransferData::Plookup(PlookupVerifyTransferData {
                    f_commit,
                    t_commit,
                    quotient_eval,
                    evaluation_challenge,
                    shifted_evaluation_challenge,
                }),
            )
            .unwrap()
    }

    fn add_witness(&mut self, witness: Self::Element) -> Result<(), Error> {
        if witness.0.len() != self.w {
            return Err(Error::WitnessLengthNotMatch(format!(
                "The length of witness is {}, not {}",
                witness.0.len(),
                self.w
            )));
        }
        if !self.hash_t.contains(&witness.0) {
            return Err(Error::WitnessNotInTable);
        }
        self.f.push(witness);
        Ok(())
    }
}

impl<F: PrimeField, P: AdditiveHomomorphicPCS<F>> Plookup<F, P>
    where P::Commitment: Add<Output=P::Commitment>
    + Mul<F, Output=P::Commitment> {
    /// Creates a new instance from a table and a PCS.
    ///
    /// # Arguments
    ///
    /// * `table`: The table.
    /// * `pcs`: The PCS.
    ///
    /// returns: `Plookup<F, P>` as a new instance.
    #[allow(dead_code)]
    fn new(table: Vec<Multiset<F>>, pcs: P) -> Self {
        let mut hash_t = HashSet::<Vec<F>>::new();
        for record in &table {
            assert_eq!(
                record.0.len(),
                table[0].0.len(),
                "The number of columns in the table must be equal"
            );
            hash_t.insert(record.0.clone());
        }
        Self {
            w: if table.is_empty() {
                0
            } else {
                table[0].0.len()
            },
            f: Vec::new(),
            t: table,
            hash_t,
            pcs,
        }
    }

    /// Calculates folded `f`, commitments for `f_i`, folded `t`, commitments for `t_i`
    ///
    /// # Arguments
    ///
    /// * `transcript`: The transcript generator.
    ///
    /// returns: `(fold_f, f_i_commit, fold_t, t_i_commit)`.
    #[allow(clippy::type_complexity)]
    fn preprocess(
        &self,
        transcript: &mut TranscriptProtocol<F>,
    ) -> (
        Multiset<F>,
        Vec<P::Commitment>,
        Multiset<F>,
        Vec<P::Commitment>,
    ) {
        let mut t = self.t.clone();
        let mut f = self.f.clone();

        f.sort();
        t.sort();
        let n = f.len();
        let d = t.len();
        if d <= n {
            t.extend(vec![t.last().unwrap().clone(); n + 1 - d]);
        } else {
            f.extend(vec![f.last().unwrap().clone(); d - n - 1]);
        }
        assert_eq!(t.len(), f.len() + 1);

        // Calculates com(f_i) and com(t_i)
        let domain = Domain::<F>::new(t.len()).unwrap();
        let mut f_i_commit: Vec<P::Commitment> = vec![];
        let mut t_i_commit: Vec<P::Commitment> = vec![];
        for i in 0..self.w {
            let mut fi: Vec<F> = vec![];
            for f_tuple in &f {
                fi.push(f_tuple.0[i]);
            }
            f_i_commit.push(self.pcs.commit(&Poly::from_evaluations(&fi, &domain)));
            transcript.append_commitment(TranscriptLabel::F_I_COMMIT, f_i_commit.last().unwrap());
            let mut ti: Vec<F> = vec![];
            for t_tuple in &t {
                ti.push(t_tuple.0[i]);
            }
            t_i_commit.push(self.pcs.commit(&Poly::from_evaluations(&ti, &domain)));
        }

        // Folds elements into field elements
        let zeta = transcript.challenge_scalar(TranscriptLabel::ZETA);
        let fold_f = Multiset(
            f.iter()
                .map(|fi| P::aggregate(&fi.0.iter().collect(), &zeta).unwrap())
                .collect(),
        );
        let fold_t = Multiset(
            t.iter()
                .map(|ti| P::aggregate(&ti.0.iter().collect(), &zeta).unwrap())
                .collect(),
        );

        (fold_f, f_i_commit, fold_t, t_i_commit)
    }

    /// Computes `Z`
    pub fn compute_accumulator_poly(
        f: &Multiset<F>,
        t: &Multiset<F>,
        h1: &Multiset<F>,
        h2: &Multiset<F>,
        beta: &F,
        gamma: &F,
        domain: &Domain<F>,
    ) -> Poly<F> {
        let n = f.0.len();
        // Calculates Z(x) for all x in domain
        let mut evaluations: Vec<F> = vec![F::one()];
        // beta + 1
        let beta_plus_one = *beta + F::one();
        // gamma * (beta + 1)
        let gamma_beta_one = *gamma * beta_plus_one;

        for i in 0..n {
            // (beta + 1)(gamma + f[i])(gamma * (beta + 1) + t[i] + beta * t[i+1])
            let mut numerator = beta_plus_one;
            numerator *= *gamma + f.0[i];
            numerator *= gamma_beta_one + t.0[i] + (*beta) * t.0[i + 1];

            // (gamma * (beta + 1) + s[i] + beta * s[i+1]) * (gamma * (beta + 1) + s[n+i] + beta * s[n+i+1])
            let mut denominator = gamma_beta_one + h1.0[i] + (*beta) * h1.0[i + 1];
            denominator *= gamma_beta_one + h2.0[i] + (*beta) * h2.0[i + 1];

            // z[i+1] = z[i] * (numerator / denominator)
            evaluations.push(*evaluations.last().unwrap() * (numerator / denominator));
        }
        assert_eq!(evaluations.len(), n + 1);
        assert_eq!(*evaluations.last().unwrap(), F::one());

        Poly::from_evaluations(&evaluations, domain)
    }

    /// Computes `h1` and `h2` from `f` and `t`.
    ///
    /// # Arguments
    ///
    /// * `f`
    /// * `t`
    ///
    /// returns: `(h1, h2)`.
    pub fn compute_h1_h2(
        f: &Multiset<F>,
        t: &Multiset<F>,
    ) -> Result<(Multiset<F>, Multiset<F>), Error> {
        // check if all elements in `f` are also in `t`
        for fi in &f.0 {
            if !t.0.contains(fi) {
                return Err(Error::WitnessNotInTable);
            }
        }

        // sort `s` by `t`
        let mut s = t.clone();
        for fi in &f.0 {
            let index = s.0.iter().position(|si| si == fi).unwrap();
            s.0.insert(index, *fi);
        }
        assert_eq!(s.0.len() % 2, 1);

        // h1[i] = s[i], i = 1...n+1
        let h1 = s.0[0..=s.0.len() / 2].to_vec();
        // h2[i] = s[i+n], i = 1..n+1
        let h2 = s.0[s.0.len() / 2..s.0.len()].to_vec();
        assert_eq!(h1.len(), h2.len());
        Ok((Multiset(h1), Multiset(h2)))
    }
}

#[cfg(test)]
mod test {
    use ark_poly::EvaluationDomain;
    use rand::Rng;

    use crate::lookup::Lookup;
    use crate::multiset::{ints_to_fields, Multiset};
    use crate::pcs::kzg10::{KZG12_381, KzgField};
    use crate::plookup::scheme::Plookup;
    use crate::plookup::transcript_label::TranscriptLabel;
    use crate::template_table::xor::XorTable;
    use crate::transcript::TranscriptProtocol;
    use crate::types::Domain;

    #[test]
    /// Tests the correctness of `compute_h1_h2` function.
    ///
    /// This test validates the correctness of splitting `(f,t)` into `(h1,h2)`
    fn compute_h1_h2() {
        let f = ints_to_fields::<KzgField>(&[5, 2, 2, 4, 4]);
        let t = ints_to_fields::<KzgField>(&[5, 3, 4, 2, 6, 7]);
        let (h1, h2) = Plookup::<KzgField, KZG12_381>::compute_h1_h2(&f, &t).unwrap();
        assert_eq!(h1, ints_to_fields::<KzgField>(&[5, 5, 3, 4, 4, 4]));
        assert_eq!(h2, ints_to_fields::<KzgField>(&[4, 2, 2, 2, 6, 7]));
    }

    #[test]
    /// Tests the `add_witness` method of the `Plookup` struct.
    ///
    /// This test creates an instance of the `XorTable` and initializes a `Plookup` object.
    /// It then adds a valid witness and verifies that adding an invalid witness results in an error.
    ///
    /// # Panics
    ///
    /// This test will panic if adding the valid witness fails.
    fn add_witness() {
        let t = XorTable::new(4).table().clone();
        let pcs = KZG12_381::new(t.len() * 2 + 3);
        let mut lookup = Plookup::<KzgField>::new(t, pcs);
        lookup
            .add_witness(Multiset(vec![
                KzgField::from(6),
                KzgField::from(5),
                KzgField::from(5 ^ 6),
            ]))
            .unwrap();
        assert!(lookup
            .add_witness(Multiset(vec![
                KzgField::from(3651),
                KzgField::from(5),
                KzgField::from(5 ^ 6),
            ]))
            .is_err());
    }

    #[test]
    /// Tests the `compute_accumulator_poly` method of the `Plookup` struct.
    ///
    /// The method is tested to ensure it processes the inputs correctly without panicking.
    fn compute_accumulator_poly() {
        let domain: Domain<KzgField> = EvaluationDomain::<KzgField>::new(4).unwrap();

        Plookup::<KzgField>::compute_accumulator_poly(
            &ints_to_fields(&[0, 2, 2]),    // f = [0,2]
            &ints_to_fields(&[0, 1, 2, 3]), // t = [0,1,2,3]
            &ints_to_fields(&[0, 0, 1, 2]), // h1
            &ints_to_fields(&[2, 2, 2, 3]), // h2
            &KzgField::from(5659),
            &KzgField::from(13954),
            &domain,
        );
    }

    #[test]
    /// Tests the `prove` and `verify` methods of the `Plookup` struct.
    ///
    /// This test runs a series of test cases to validate the proof generation and verification process of the `Plookup` scheme.
    ///
    /// # Panics
    ///
    /// This test will panic if adding a witness or generating a proof fails, or if the verification of a proof does not pass.
    fn prove_and_verify() {
        const TEST_CASES: usize = 5;
        let t = XorTable::new(4).table().clone();

        let mut rnd = rand::thread_rng();
        let l = t.len();

        for test in 0..TEST_CASES {
            let mut transcript = TranscriptProtocol::<KzgField>::new(TranscriptLabel::NAME);
            let pcs = KZG12_381::new(t.len() * 2 + 5);
            let mut lookup = Plookup::<KzgField>::new(t.clone(), pcs);
            let w = rnd.gen_range(1..=l);
            let mut v = vec![];
            for _ in 0..w {
                let idx = rnd.gen_range(0..l);
                v.push(idx);
            }
            for idx in &v {
                lookup.add_witness(t[*idx].clone()).expect("");
            }
            let proof = lookup.prove(&mut transcript);
            let mut verifier_transcript =
                TranscriptProtocol::<KzgField>::new(TranscriptLabel::NAME);
            assert!(lookup.verify(&mut verifier_transcript, &proof));
            println!("Test {} passed, v = {:?}", test, v);
        }
    }
}

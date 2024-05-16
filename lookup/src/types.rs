use crate::pcs::base_pcs::BasePCS;
use crate::plookup::types::{PlookupProof, PlookupProveTransferData, PlookupVerifyTransferData};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::Radix2EvaluationDomain;

pub type Poly<F> = DensePolynomial<F>;
pub type Domain<F> = Radix2EvaluationDomain<F>;

pub enum LookupProofTransferData<F: PrimeField> {
    Plookup(PlookupProveTransferData<F>),
}

pub enum LookupVerifyTransferData<F: PrimeField, Commitment> {
    Plookup(PlookupVerifyTransferData<F, Commitment>),
}

pub enum LookupProof<'a, F: PrimeField, P: BasePCS<F>> {
    Plookup(&'a PlookupProof<F, P>),
}

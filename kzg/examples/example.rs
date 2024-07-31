use ark_bls12_381::Fr;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalDeserialize;
use kzg::scheme::KzgScheme;
use kzg::srs::Srs;
use kzg::types::G1Point;
use hex;
use kzg::commitment::KzgCommitment;
use kzg::opening::KzgOpening;

fn main() {
    // trusted setup
    let srs = Srs::new(10);
    let scheme = KzgScheme::new(srs);

    // polynomial x^3 + 3x + 5

    let coeff = vec![Fr::from(5), Fr::from(3), Fr::from(0), Fr::from(1)];
    let poly = DensePolynomial::from_coefficients_vec(coeff);
    let v = poly.evaluate(&Fr::from(1));
    assert_eq!(v, Fr::from(9));

    // commit poly
    let commitment = scheme.commit(&poly);
    // opening point at p = 4.
    let opening_pos = Fr::from(4);
    let opening = scheme.open(&poly, opening_pos);

    assert!(scheme.verify(&commitment, &opening, opening_pos));

    let z = "29ef6432c157829fd5a402d6fd6909a502ea73181df1dca79cfd71f42014c505";
    let y = "a5e1b0055dddd20d976ae79ffb584c472911787e3427fa8934991403a516691b";
    let commitment = "996396e6cd13b33a9cc52ebd69e0aadca543794a449dd39de01d0cb2c09747709afe0e5a38dc2222185dbf7eba5f5088";
    let proof = "8664b3057bc3aefaf110db484fdc0c422c58209c7f8a331a4c5f853a9e37d0de5f02ec0289d7d0634e49ef813fb8e84d";

    let z_decode = hex::decode(z).expect("");
    let y_decode = hex::decode(y).expect("");
    let commitment_decode = hex::decode(commitment).expect("");
    let proof_decode = hex::decode(proof).expect("");

    let z_binding: &[u8] = z_decode.as_ref();
    let y_binding: &[u8] = y_decode.as_ref();
    let commitment_binding: &[u8] = commitment_decode.as_ref();
    let proof_binding: &[u8] = proof_decode.as_ref();

    let cmt = G1Point::deserialize_compressed(commitment_binding).expect("");
    let prf = G1Point::deserialize_compressed(proof_binding).expect("");
    let zz = Fr::deserialize_compressed(z_binding).unwrap();
    let yy = Fr::deserialize_compressed(y_binding).unwrap();
    eprintln!("cmt = {:#?}", cmt);
    eprintln!("prf = {:#?}", prf);
    eprintln!("zz = {:#?}", zz);
    eprintln!("yy = {:#?}", yy);

    assert!(scheme.verify(
        &KzgCommitment {
            0: cmt
        },
        &KzgOpening {
            0: prf,
            1: yy
        },
        zz
    ));
}

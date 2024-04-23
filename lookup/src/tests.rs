#[cfg(test)]
pub mod tests {
    use ark_bls12_381::Fr;
    use kzg::commitment::KzgCommitment;
    use kzg::opening::KzgOpening;
    use kzg::scheme::KzgScheme;
    use kzg::srs::Srs;
    use crate::commitment::PCS;
    use crate::types::Poly;

    pub type F = ark_bls12_381::Fr;
    pub struct KZG12_381 {
        scheme: KzgScheme
    }

    impl PCS<F> for KZG12_381 {
        type Commitment = KzgCommitment;
        type Opening = KzgOpening;

        fn new() -> Self {
            Self {
                scheme: KzgScheme::new(Srs::new(10)),
            }
        }

        fn commit(&self, poly: &Poly<Fr>) -> KzgCommitment {
            self.scheme.commit(poly)
        }

        fn open(&self, poly: &Poly<Fr>, z: Fr) -> KzgOpening {
            self.scheme.open(poly.clone(), z)
        }
    }
}
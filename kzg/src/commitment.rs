use crate::types::G1Point;

/// Commitment contains result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgCommitment(pub G1Point);

impl KzgCommitment {
    /// A reference to the inner `G1Point` contained within the commitment.
    pub fn inner(&self) -> &G1Point {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use ark_bls12_381::Fr;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::One;
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use crate::commitment::KzgCommitment;
    use crate::opening::KzgOpening;
    use crate::scheme::KzgScheme;
    use crate::srs::Srs;
    use crate::types::{G1Point, Poly};

    #[test]
    /// Tests the commitment functionality in the KZG scheme.
    ///
    /// This test verifies the correctness of committing to a polynomial,
    /// opening the commitment, and verifying the opening.
    fn commit() {
        let secret = Fr::from(2);
        let srs = Srs::new_from_secret(secret, 10);
        let scheme = KzgScheme::new(srs);
        let poly = Poly::from_coefficients_slice(&[1.into(), 2.into(), 3.into()]);
        let commitment = scheme.commit(&poly);
        let d = Fr::one();

        assert_eq!(poly.evaluate(&d), 6.into());

        assert_eq!(
            commitment.0,
            G1Point::generator()
                .mul(poly.evaluate(&secret))
                .into_affine()
        );
        let opening = scheme.open(poly, d);
        assert!(scheme.verify(&commitment, &opening, d));
    }

    #[test]
    /// Tests the scalar multiplication of commitments.
    ///
    /// This test validates the correctness of scalar multiplying a commitment
    /// by a factor in the KZG scheme.
    fn scalar_mul() {
        let srs = Srs::new(5);
        let scheme = KzgScheme::new(srs);
        let coeffs = [1, 2, 3, 4, 5].map(Fr::from);
        let poly = Poly::from_coefficients_slice(&coeffs);
        let commit1 = scheme.commit(&poly);
        let factor = Fr::from(9);
        let poly2 = poly.mul(factor);
        let commit2 = scheme.commit(&poly2);
        assert_eq!(commit1 * factor, commit2);
    }

    #[test]
    /// Tests the aggregation of commitments.
    ///
    /// This test validates the correctness of aggregating multiple commitments
    /// by a random challenge
    fn aggregate_commitments() {
        let srs = Srs::new(5);
        let scheme = KzgScheme::new(srs);
        let f1 = Poly::from_coefficients_slice(&[1, 2, 3, 4, 5].map(Fr::from));
        let f2 = Poly::from_coefficients_slice(&[1, 2, 3, 4, 8].map(Fr::from));
        let c1 = scheme.commit(&f1);
        let c2 = scheme.commit(&f2);
        let challenge: u128 = StdRng::from_entropy().gen();
        let challenge = Fr::from(challenge);
        let batch = KzgScheme::aggregate_commitments(&vec![&c1, &c2], &challenge);
        assert_eq!(batch.0, c1.0 + c2.0 * challenge);
    }

    #[test]
    /// Tests the batching of verifications.
    ///
    /// This test validates the correctness of verifying multiple proofs
    fn batch_verify() {
        let srs = Srs::new(5);
        let scheme = KzgScheme::new(srs);
        let f1 = Poly::from_coefficients_slice(&[1, 2, 3, 4, 5].map(Fr::from));
        let f2 = Poly::from_coefficients_slice(&[1, 8, 3, 4, 8].map(Fr::from));
        let f3 = Poly::from_coefficients_slice(&[12, 8, 3, 9, 8].map(Fr::from));
        let f4 = Poly::from_coefficients_slice(&[95, 8, 0, 9, 8].map(Fr::from));
        let f5 = Poly::from_coefficients_slice(&[12, 0, 3, 9, 0].map(Fr::from));
        let f: Vec<Poly> = vec![f1, f2, f3, f4, f5];
        let z = [
            Fr::from(12),
            Fr::from(4),
            Fr::from(2003),
            Fr::from(13),
            Fr::from(9),
        ];
        let openings: Vec<KzgOpening> = f
            .iter()
            .zip(z)
            .map(|(f_i, z_i)| scheme.open(f_i.clone(), z_i))
            .collect();
        let c: Vec<KzgCommitment> = f.iter().map(|f_i| scheme.commit(f_i)).collect();
        let mut rng = StdRng::from_entropy();
        assert!(scheme.batch_verify(c.as_slice(), &z, &openings, &mut rng));
    }
}

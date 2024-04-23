use ark_ff::PrimeField;

/// Fold a vector into one element using a random challenge
///
/// Eg. for `v = [A,B,C]` and a random challenge `k`
///
/// The aggregate is k^0 *A + k^1 * B + k^2 * C
pub fn fold<F: PrimeField>(v: &Vec<F>, zeta: F) -> F {
    let mut pow = F::one();
    let mut res = F::zero();
    for e in v {
        res += *e * pow;
        pow *= zeta;
    }
    return res;
}
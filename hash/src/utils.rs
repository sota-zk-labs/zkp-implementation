use num_bigint::BigUint;
pub fn add_mod(a: &BigUint, b: &BigUint, q: &BigUint) -> BigUint {
    (a + b) % q
}

pub fn mul_mod(a: &BigUint, b: &BigUint, q: &BigUint) -> BigUint {
    (a * b) % q
}

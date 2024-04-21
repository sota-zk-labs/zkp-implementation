use num_bigint::BigUint;
use num_traits::Num;

use super::reinforced_concrete_instances::{CONSTANTS_STR, DIVISORS, Q_STR, SBOX};

#[derive(Debug, Clone)]
pub struct ReinforcedConcreteParams {
    pub q: BigUint,
    pub round_constants: Vec<BigUint>,
    pub divisors: Vec<u16>,
    pub sbox: Vec<u16>,
}

impl ReinforcedConcreteParams {
    pub fn new() -> Self {
        let q = BigUint::from_str_radix(Q_STR, 10).unwrap();
        let round_constants = CONSTANTS_STR
            .iter()
            .map(|&s| BigUint::from_str_radix(s, 10).unwrap())
            .collect::<Vec<_>>();
        let divisors = DIVISORS.to_vec();
        let sbox = SBOX.to_vec();

        ReinforcedConcreteParams {
            q,
            round_constants,
            divisors,
            sbox,
        }
    }
}

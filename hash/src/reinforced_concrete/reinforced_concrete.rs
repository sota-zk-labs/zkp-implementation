use super::reinforced_concrete_params::ReinforcedConcreteParams;
use crate::utils::{add_mod, mul_mod};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

#[derive(Clone, Debug)]
pub struct ReinforcedConcrete {
    params: ReinforcedConcreteParams,
}

impl ReinforcedConcrete {
    pub fn new(params: ReinforcedConcreteParams) -> Self {
        ReinforcedConcrete { params }
    }

    pub fn concrete(&self, state: &[BigUint], iteration: usize) -> Vec<BigUint> {
        let q = &self.params.q;
        let round_constants = &self.params.round_constants;

        let sum = add_mod(&add_mod(&state[0], &state[1], q), &state[2], q);

        let mut out_state = vec![BigUint::from(0u64); 3];

        for i in 0..3 {
            out_state[i] = add_mod(
                &add_mod(&sum, &state[i], q),
                &round_constants[iteration * 3 + i],
                q,
            );
        }

        out_state
    }

    // Bricks layer
    pub fn bricks(&self, state: &[BigUint]) -> Vec<BigUint> {
        let q = &self.params.q;
        let state0_square = mul_mod(&state[0], &state[0], q);
        let state1_square = mul_mod(&state[1], &state[1], q);

        let mut out_state = vec![BigUint::from(0u64); 3];

        out_state[0] = mul_mod(&mul_mod(&state0_square, &state0_square, q), &state[0], q);
        out_state[1] = mul_mod(
            &add_mod(
                &add_mod(&state0_square, &state[0], q),
                &BigUint::from(2u64),
                q,
            ),
            &state[1],
            q,
        );
        out_state[2] = mul_mod(
            &add_mod(
                &state1_square,
                &add_mod(
                    &mul_mod(&state[1], &BigUint::from(3u64), q),
                    &BigUint::from(4u64),
                    q,
                ),
                q,
            ),
            &state[2],
            q,
        );

        out_state
    }

    pub fn decompose(&self, state: &[BigUint]) -> Vec<Vec<BigUint>> {
        let divisors = &self.params.divisors;
        let mut out_state = vec![vec![BigUint::from(0u64); 27]; 3];

        for i in 0..3 {
            let mut repr = state[i].clone();
            let mut out_state_for_round = vec![BigUint::from(0u64); 27];

            for j in (0..27).rev() {
                if j == 0 {
                    out_state_for_round[j] = repr.clone();
                    break; // otherwise arithmetic underflow/overflow
                } else {
                    let divisor = BigUint::from(divisors[j] as u64);
                    out_state_for_round[j] = repr.clone() % &divisor;
                    repr = &repr / &divisor;
                }
            }

            out_state[i] = out_state_for_round;
        }

        out_state
    }

    // Lookup function
    pub fn lookup(&self, state: &[Vec<BigUint>]) -> Vec<Vec<BigUint>> {
        let sbox = &self.params.sbox;
        let mut out_state = vec![vec![BigUint::from(0u64); 27]; 3];

        for i in 0..3 {
            let mut out_state_for_round = vec![BigUint::from(0u64); 27];
            for j in 0..27 {
                out_state_for_round[j] = BigUint::from(sbox[state[i][j].to_usize().unwrap()]);
            }
            out_state[i] = out_state_for_round;
        }

        out_state
    }

    // Compose function
    pub fn compose(&self, state: &[Vec<BigUint>]) -> Vec<BigUint> {
        let divisors = &self.params.divisors;
        let q = &self.params.q;
        let mut out_state = vec![BigUint::from(0u64); 3];

        for i in 0..3 {
            let mut tmp = vec![BigUint::from(0u64); 53];
            for k in 0..27 {
                tmp[k] = state[i][k].clone();
            }

            for j in 1..27 {
                let mulmod_result = mul_mod(&tmp[2 * j - 2], &BigUint::from(divisors[j]), q);
                tmp[2 * j - 1] = mulmod_result;
                tmp[2 * j] = add_mod(&tmp[2 * j - 1], &state[i][j], q);
            }
            out_state[i] = tmp[52].clone();
        }

        out_state
    }

    pub fn bars(&self, state: &[BigUint]) -> Vec<BigUint> {
        let decomposed = self.decompose(state);
        let looked_up = self.lookup(&decomposed);
        let out_state = self.compose(&looked_up);

        out_state
    }

    pub fn hash(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let mut state = vec![BigUint::from(0u64); 3];
        state[0] = a.clone();
        state[1] = b.clone();
        state[2] = BigUint::from(0u64);

        state = self.concrete(&state, 0);

        for i in 1..=3 {
            state = self.bricks(&state);
            state = self.concrete(&state, i);
        }

        state = self.bars(&state);

        state = self.concrete(&state, 4);

        for i in 5..=7 {
            state = self.concrete(&self.bricks(&state), i);
        }

        state[0].clone()
    }
}

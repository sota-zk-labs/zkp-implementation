use ark_ff::PrimeField;

use crate::utils;

#[derive(Clone, Debug)]
pub struct PoseidonParams<F: PrimeField> {
    pub(crate) t: usize, // state size
    pub(crate) d: usize, // sbox degree
    pub(crate) rounds_f_beginning: usize, // number of full rounds at the beginning
    pub(crate) rounds_p: usize, // number of partial rounds performed after the full rounds
    #[allow(dead_code)]
    pub(crate) rounds_f_end: usize, // number of full rounds at the end
    pub(crate) rounds: usize, // total number of rounds
    pub(crate) mds: Vec<Vec<F>>, // store the MDS used in the hash function
    pub(crate) round_constants: Vec<Vec<F>>, // store the round constants used in the hash function
    pub(crate) opt_round_constants: Vec<Vec<F>>, // optimized
    pub(crate) w_hat: Vec<Vec<F>>,               // optimized
    pub(crate) v: Vec<Vec<F>>,                   // optimized
    pub(crate) m_i: Vec<Vec<F>>,                 // optimized
}

impl<F: PrimeField> PoseidonParams<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        t: usize, // state size
        d: usize, // sbox degree
        rounds_f: usize, // number of full rounds
        rounds_p: usize, // number of partial rounds
        mds: &[Vec<F>], // MDS matrix
        round_constants: &[Vec<F>], // round constants
    ) -> Self {
        assert!(d == 3 || d == 5 || d == 7);
        assert_eq!(mds.len(), t);
        assert_eq!(rounds_f % 2, 0);
        let r = rounds_f / 2;
        let rounds = rounds_f + rounds_p;

        let (m_i_, v_, w_hat_) = Self::equivalent_matrices(mds, t, rounds_p);
        let opt_round_constants_ = Self::equivalent_round_constants(round_constants, mds, r, rounds_p);

        PoseidonParams {
            t,
            d,
            rounds_f_beginning: r,
            rounds_p,
            rounds_f_end: r,
            rounds,
            mds: mds.to_owned(),
            round_constants: round_constants.to_owned(),
            opt_round_constants: opt_round_constants_,
            w_hat: w_hat_,
            v: v_,
            m_i: m_i_,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn equivalent_matrices(
        mds: &[Vec<F>],
        t: usize,
        rounds_p: usize,
    ) -> (Vec<Vec<F>>, Vec<Vec<F>>, Vec<Vec<F>>) {
        let mut w_hat = Vec::with_capacity(rounds_p);
        let mut v = Vec::with_capacity(rounds_p);
        let mut m_i = vec![vec![F::zero(); t]; t];

        let mds_ = utils::mat_transpose(mds);
        let mut m_mul = mds_.clone();

        for _ in 0..rounds_p {
            // calc m_hat, w and v
            let mut m_hat = vec![vec![F::zero(); t - 1]; t - 1];
            let mut w = vec![F::zero(); t - 1];
            let mut v_ = vec![F::zero(); t - 1];
            v_[..(t-1)].clone_from_slice(&m_mul[0][1..t]);
            for row in 1..t {
                for col in 1..t {
                    m_hat[row - 1][col - 1] = m_mul[row][col];
                }
                w[row - 1] = m_mul[row][0];
            }

            // calc_w_hat


        }
    }

    pub fn equivalent_round_constants(

    ) -> Vec<Vec<F>> {

    }

    pub fn mat_vec_mul() -> Vec<F> {

    }

    pub fn mat_mat_mul() -> Vec<Vec<F>> {

    }
}

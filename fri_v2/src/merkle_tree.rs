use crate::errors::FriError;
use crate::hasher::Hasher;
use ark_ff::PrimeField;
use std::marker::PhantomData;

pub struct FriMerkleTree<T, H>
where
    H: Hasher<T>,
    T: PrimeField,
{
    pub nodes: Vec<Vec<T>>,

    _phantom: PhantomData<H>,
}

impl<T: PrimeField, H: Hasher<T>> FriMerkleTree<T, H> {
    pub fn new(vals: Vec<T>) -> Result<Self, FriError> {
        if vals.len() > 1 && vals.len() % 2 != 0 {
            return Err(FriError::UnevenTree);
        }

        let mut cur = vals;
        let mut nodes = vec![];
        while cur.len() > 1 {
            let a = cur
                .chunks(2)
                .map(|data| {
                    let mut di = H::default();
                    di.digest_vec(data);
                    di.finalize()
                })
                .collect::<Vec<_>>();
            nodes.push(cur);
            cur = a;
        }
        nodes.push(cur);

        Ok(Self {
            nodes,
            _phantom: Default::default(),
        })
    }
}

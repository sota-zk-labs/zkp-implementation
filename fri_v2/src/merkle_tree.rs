use crate::hasher::FRIHasher;

pub struct FriMerkleTree<T, H>
where
    H: FRIHasher<T>,
{
    // pub root: T,
    // pub leaves: Vec<T>,
    pub nodes: Vec<Vec<T>>,
}

impl<T, H: FRIHasher<T>> FriMerkleTree<T, H> {
    pub fn new(vals: Vec<T>) -> Self {
        let mut cur = vals;
        let mut nodes = vec![];
        while cur.len() > 0 {
            let a = cur.chunks(2).map(|data| H::hash(data)).collect::<Vec<_>>();
            nodes.push(cur);
            cur = a;
        }

        Self { nodes }
    }
}

pub trait FRIHasher<T> {
    fn hash(data: &T) -> T;
}


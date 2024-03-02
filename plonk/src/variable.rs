pub enum Variable<F> {
    Index(usize),
    Value(F),
}
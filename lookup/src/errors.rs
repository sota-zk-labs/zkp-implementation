/// Defines all possible errors that can be encountered in lookup schemes.
#[derive(Debug)]
pub enum Error {
    /// Error indicating that elements cannot be aggregated.
    NonAggregatable,
    /// Error indicating that an incorrect lookup scheme was used.
    WrongLookupScheme,
    /// Error indicating that the length of a witness does not match the element length in the table
    WitnessLengthNotMatch(String),
    /// Error indicating that a witness is not found in the table.
    WitnessNotInTable,
    /// Error indicating that a vector is empty.
    EmptyVec,
    /// Error indicating that a polynomial does not fit in the specified domain.
    PolyNotFitInDomain(String),
}

use thiserror::Error;
#[derive(Error, Debug)]
pub enum FriError {
    #[error("number of leaves must be even")]
    UnevenTree,

    #[error("unknown error")]
    Unknown,
}
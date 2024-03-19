#[allow(dead_code)]
#[derive(Debug)]
pub enum CustomError {
    AssignmentIndexMissing,
}

impl std::fmt::Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &*self {
            CustomError::AssignmentIndexMissing => {
                write!(f, "Must init assignment before use its index")
            }
        }
    }
}

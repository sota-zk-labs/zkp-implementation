use crate::nifs::{NIFSProof};
use crate::r1cs::{FInstance};

pub struct IVCProof{
    u: FInstance,
    u_proof: NIFSProof,
    big_u: FInstance,
    big_u_proof: NIFSProof,
}

// pub struct IVC {
//     srs: Srs,
//     augmented_circuit: AugmentedCircuit,
// }


use ark_ff::fields::{Fp64, MontBackend, MontConfig};

// this Goldilocks implementation is inspired by Electron-Labs: https://github.com/Electron-Labs/fri-commitment
#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

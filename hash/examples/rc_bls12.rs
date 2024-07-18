use hash::reinforced_concrete::{
    reinforced_concrete::ReinforcedConcrete, reinforced_concrete_params::ReinforcedConcreteParams,
};

use num_bigint::BigUint;
fn main() {
    // Print result
    let rc_params = ReinforcedConcreteParams::new();
    let rc = ReinforcedConcrete::new(rc_params);

    // Sample inputs a and b
    let a = BigUint::from(123456u64);
    let b = BigUint::from(789012u64);

    // Compute hash
    let res = rc.hash(&a, &b);

    // Print result
    println!("Hash result: {}", res);
}

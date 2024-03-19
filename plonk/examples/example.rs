use ark_bls12_381::Fr;
extern crate plonk;
use plonk::circuit;
fn main() {
    // Function: xy + 3x^2 + xyz = 11

    // init a new circuit
    let mut circuit = circuit::Circuit::new();

    // create gates for this circuit
    let _ = circuit.add_a_mult_gate((0,1,Fr::from(1)), (1,0,Fr::from(2)), (0,3,Fr::from(2)), Fr::from(0));
    let _ = circuit.add_a_mult_gate((1,1,Fr::from(1)), (0,0,Fr::from(1)), (0,2,Fr::from(1)), Fr::from(0));
    let _ = circuit.add_a_mult_gate((2,1,Fr::from(1)), (2,6,Fr::from(3)), (1,3,Fr::from(3)), Fr::from(0));
    let _ = circuit.add_an_add_gate((0,4,Fr::from(2)), (2,2,Fr::from(3)), (0,5,Fr::from(5)), Fr::from(0));

    let _ = circuit.add_a_mult_gate((2,0,Fr::from(2)), (1,4,Fr::from(3)), (1,5,Fr::from(6)), Fr::from(0));
    let _ = circuit.add_an_add_gate((2,3,Fr::from(5)), (2,4,Fr::from(6)), (2,5,Fr::from(11)), Fr::from(0));
    let _ = circuit.add_a_constant_gate((0,6, Fr::from(3)), (1,6, Fr::from(0)), (1,2, Fr::from(3)), Fr::from(0));

    // compile the circuit
    let compile_circuit = circuit.compile_circuit();

    // generate proof
    let proof = compile_circuit.prove();

    // verify proof
    compile_circuit.verify(proof);
}
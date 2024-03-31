use ark_bls12_381::Fr;
use plonk::circuit;
use plonk::prover;
use plonk::verifier;
fn main() {
    // Function: xy + 3x^2 + xyz = 11

    // init a new circuit
    let mut circuit = circuit::Circuit::new();

    // create gates for this circuit
    let _ = circuit.add_multiplication_gate((0, 1, Fr::from(1)), (1, 0, Fr::from(2)), (0, 3, Fr::from(2)), Fr::from(0));
    let _ = circuit.add_multiplication_gate((1, 1, Fr::from(1)), (0, 0, Fr::from(1)), (0, 2, Fr::from(1)), Fr::from(0));
    let _ = circuit.add_multiplication_gate((2, 1, Fr::from(1)), (2, 6, Fr::from(3)), (1, 3, Fr::from(3)), Fr::from(0));
    let _ = circuit.add_addition_gate((0, 4, Fr::from(2)), (2, 2, Fr::from(3)), (0, 5, Fr::from(5)), Fr::from(0));

    let _ = circuit.add_multiplication_gate((2, 0, Fr::from(2)), (1, 4, Fr::from(3)), (1, 5, Fr::from(6)), Fr::from(0));
    let _ = circuit.add_addition_gate((2, 3, Fr::from(5)), (2, 4, Fr::from(6)), (2, 5, Fr::from(11)), Fr::from(0));
    let _ = circuit.add_constant_gate((0, 6, Fr::from(3)), (1, 6, Fr::from(0)), (1, 2, Fr::from(3)), Fr::from(0));

    // compile the circuit
    let compile_circuit = circuit.compile_circuit().unwrap();

    // generate proof
    let proof = prover::generate_proof(&compile_circuit);

    // verify proof
    assert!(verifier::verify(proof, compile_circuit).is_ok());
}
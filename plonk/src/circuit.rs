use std::collections::HashMap;
use std::sync::Arc;

use ark_bls12_381::Fr;
use ark_ff::One;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};

use crate::compiled_circuit::CompiledCircuit;
use crate::constraint::{CopyConstraints, GateConstraints};
use crate::gate::{Gate, Position};

/// Represents a circuit consisting of gates and values.
#[derive(PartialEq, Debug)]
pub struct Circuit {
    gates: Vec<Gate>,
    vals: Vec<Arc<Vec<Fr>>>,
}

impl Default for Circuit {
    fn default() -> Self {
        Self {
            gates: Vec::default(),
            vals: vec![
                Arc::new(Vec::default()),
                Arc::new(Vec::default()),
                Arc::new(Vec::default()),
            ],
        }
    }
}

impl Circuit {
    pub const VEC_A: &'static str = "vec_a";
    pub const VEC_B: &'static str = "vec_b";
    pub const VEC_C: &'static str = "vec_c";
    pub const VEC_QL: &'static str = "vec_ql";
    pub const VEC_QR: &'static str = "vec_qr";
    pub const VEC_QM: &'static str = "vec_qm";
    pub const VEC_QO: &'static str = "vec_qo";
    pub const VEC_QC: &'static str = "vec_qc";
    pub const VEC_PI: &'static str = "vec_pi";
}

impl Circuit {
    /// Adds a gate to the circuit.
    fn add_gate(
        &mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        gate_type: GateType,
        pi: Fr,
    ) {
        // Push the values to the corresponding vectors
        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        // Create the gate based on the gate type and push it to the gates vector
        let gate = match gate_type {
            GateType::Addition => Gate::new_add_gate(
                Position::Pos(a.0, a.1),
                Position::Pos(b.0, b.1),
                Position::Pos(c.0, c.1),
                Some(pi),
            ),
            GateType::Multiplication => Gate::new_mul_gate(
                Position::Pos(a.0, a.1),
                Position::Pos(b.0, b.1),
                Position::Pos(c.0, c.1),
                Some(pi),
            ),
            GateType::Constant => Gate::new_constant_gate(
                Position::Pos(a.0, a.1),
                Position::Pos(b.0, b.1),
                Position::Pos(c.0, c.1),
                a.2,
                Some(pi),
            ),
        };
        self.gates.push(gate);
    }

    /// Adds an addition gate to the circuit.
    pub fn add_addition_gate(
        &mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ) {
        self.add_gate(a, b, c, GateType::Addition, pi);
    }

    /// Adds a multiplication gate to the circuit.
    pub fn add_multiplication_gate(
        &mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ) {
        self.add_gate(a, b, c, GateType::Multiplication, pi);
    }

    /// Adds a constant gate to the circuit.
    pub fn add_constant_gate(
        &mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ) {
        self.add_gate(a, b, c, GateType::Constant, pi);
    }

    /// Gets the assignment of the circuit.
    pub(crate) fn get_assignment(&self) -> HashMap<&'static str, Vec<Fr>> {
        let mut result = HashMap::default();
        result.insert(Circuit::VEC_A, vec![]);
        result.insert(Circuit::VEC_B, vec![]);
        result.insert(Circuit::VEC_C, vec![]);
        result.insert(Circuit::VEC_QL, vec![]);
        result.insert(Circuit::VEC_QR, vec![]);
        result.insert(Circuit::VEC_QM, vec![]);
        result.insert(Circuit::VEC_QO, vec![]);
        result.insert(Circuit::VEC_QC, vec![]);
        result.insert(Circuit::VEC_PI, vec![]);

        for (i, gate) in self.gates.iter().enumerate() {
            if gate.is_dummy_gate() {
                continue;
            }
            result.get_mut(Self::VEC_A).unwrap().push(self.vals[0][i]);
            result.get_mut(Self::VEC_B).unwrap().push(self.vals[1][i]);
            result.get_mut(Self::VEC_C).unwrap().push(self.vals[2][i]);
            result.get_mut(Self::VEC_QL).unwrap().push(gate.q_l);
            result.get_mut(Self::VEC_QR).unwrap().push(gate.q_r);
            result.get_mut(Self::VEC_QM).unwrap().push(gate.q_m);
            result.get_mut(Self::VEC_QO).unwrap().push(gate.q_o);
            result.get_mut(Self::VEC_QC).unwrap().push(gate.q_c);
            result.get_mut(Self::VEC_PI).unwrap().push(gate.pi);
        }
        result
    }

    /// Pads the circuit with dummy gates to make its size a power of 2.
    fn pad_circuit(&mut self) {
        let len = self.gates.len();

        let exponent = (len - 1).ilog2() + 1;
        let new_len = 1 << exponent;

        for _ in len..new_len {
            self.add_dummy_gate();
        }
    }

    /// Adds a dummy gate to the circuit.
    fn add_dummy_gate(&mut self) {
        let gate = Gate::new_dummy_gate();
        self.gates.push(gate);
    }

    /// Compiles the circuit into a compiled circuit.
    pub fn compile(mut self) -> Result<CompiledCircuit, String> {
        self.pad_circuit();

        let circuit_size = self.gates.len();
        let domain = GeneralEvaluationDomain::<Fr>::new(circuit_size).unwrap();
        let assignment = self.get_assignment();

        let mut interpolated_assignment = assignment
            .into_iter()
            .map(|(k, v)| (k, Evaluations::from_vec_and_domain(v, domain).interpolate()))
            .collect::<HashMap<_, _>>();

        let gate_constraints = GateConstraints::new(
            interpolated_assignment.remove(Circuit::VEC_A).unwrap(),
            interpolated_assignment.remove(Circuit::VEC_B).unwrap(),
            interpolated_assignment.remove(Circuit::VEC_C).unwrap(),
            interpolated_assignment.remove(Circuit::VEC_QL).unwrap(),
            interpolated_assignment.remove(Circuit::VEC_QR).unwrap(),
            interpolated_assignment.remove(Circuit::VEC_QO).unwrap(),
            interpolated_assignment.remove(Circuit::VEC_QM).unwrap(),
            interpolated_assignment.remove(Circuit::VEC_QC).unwrap(),
            interpolated_assignment.remove(Circuit::VEC_PI).unwrap(),
        );

        let copy_constraints = self.cal_permutation();

        Ok(CompiledCircuit::new(
            gate_constraints,
            copy_constraints,
            circuit_size,
        ))
    }

    /// Calculates the Copy constraints.
    fn cal_permutation(&self) -> CopyConstraints {
        let len = self.gates.len();
        let domain = GeneralEvaluationDomain::<Fr>::new(len).unwrap();
        let roots = domain.elements().collect::<Vec<_>>();
        let (coset1, coset2, k1, k2) = self.find_cosets(&roots);

        // create sigma_1, sigma_2, and sigma_3
        let mut sigma_1 = roots.clone();
        let mut sigma_2 = coset1.clone();
        let mut sigma_3 = coset2.clone();

        for (index, gate) in self.gates.iter().enumerate() {
            if gate.is_dummy_gate() {
                continue;
            }

            let map_element = |pos: &Position| -> Fr {
                match pos {
                    Position::Pos(0, i_2) => roots[*i_2],
                    Position::Pos(1, i_2) => coset1[*i_2],
                    Position::Pos(2, i_2) => coset2[*i_2],
                    _ => panic!("Invalid position"),
                }
            };

            sigma_1[index] = map_element(gate.get_a_wire());
            sigma_2[index] = map_element(gate.get_b_wire());
            sigma_3[index] = map_element(gate.get_c_wire());
        }

        let s_sigma_1 = Evaluations::from_vec_and_domain(sigma_1, domain).interpolate();
        let s_sigma_2 = Evaluations::from_vec_and_domain(sigma_2, domain).interpolate();
        let s_sigma_3 = Evaluations::from_vec_and_domain(sigma_3, domain).interpolate();

        CopyConstraints::new(s_sigma_1, s_sigma_2, s_sigma_3, k1, k2)
    }

    /// Finds the cosets for permutation.
    fn find_cosets(&self, roots: &[Fr]) -> (Vec<Fr>, Vec<Fr>, Fr, Fr) {
        let k1 = roots[0] + Fr::one();
        let k2 = k1 + Fr::one();
        let coset1 = roots.iter().map(|root| *root * k1).collect();
        let coset2 = roots.iter().map(|root| *root * k2).collect();

        (coset1, coset2, k1, k2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_circuit_test() {
        let mut circuit = Circuit::default();
        circuit.add_multiplication_gate(
            (0, 0, Fr::from(1)),
            (0, 0, Fr::from(1)),
            (2, 0, Fr::from(1)),
            Fr::from(0),
        );
        circuit.add_multiplication_gate(
            (0, 0, Fr::from(1)),
            (1, 1, Fr::from(2)),
            (2, 1, Fr::from(2)),
            Fr::from(0),
        );
        circuit.add_addition_gate(
            (2, 1, Fr::from(2)),
            (1, 2, Fr::from(-3)),
            (2, 2, Fr::from(-1)),
            Fr::from(0),
        );
        circuit.add_addition_gate(
            (2, 0, Fr::from(1)),
            (2, 2, Fr::from(-1)),
            (2, 3, Fr::from(0)),
            Fr::from(0),
        );

        assert_eq!(circuit.vals[0][2], circuit.vals[2][1]);
    }
}

/// Enum representing different types of gates.
enum GateType {
    Addition,
    Multiplication,
    Constant,
}

use std::collections::HashMap;

use ark_bls12_381::Fr;
use ark_ff::One;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};

use crate::constraint::{CopyConstraints, GateConstraints};
use crate::gate::{Gate, Position};

/// Represents a circuit consisting of gates and values.
#[derive(PartialEq, Debug, Default)]
pub struct CPICircuit {
    gates: Vec<Gate>,
}

impl CPICircuit {
    // Constants for vector names
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

impl CPICircuit {
    /// Adds an addition gate to the circuit.
    pub fn add_addition_gate(
        mut self,
        a: (usize, usize),
        b: (usize, usize),
        c: (usize, usize),
        pi: Fr,
    ) -> Self {
        self.gates.push(Gate::new_add_gate(
            Position::Pos(a.0, a.1),
            Position::Pos(b.0, b.1),
            Position::Pos(c.0, c.1),
            Some(pi),
        ));
        self
    }

    /// Adds a multiplication gate to the circuit.
    pub fn add_multiplication_gate(
        mut self,
        a: (usize, usize),
        b: (usize, usize),
        c: (usize, usize),
        pi: Fr,
    ) -> Self {
        self.gates.push(Gate::new_mul_gate(
            Position::Pos(a.0, a.1),
            Position::Pos(b.0, b.1),
            Position::Pos(c.0, c.1),
            Some(pi),
        ));
        self
    }

    /// Adds a constant gate to the circuit.
    pub fn add_constant_gate(
        mut self,
        a: (usize, usize),
        b: (usize, usize),
        c: (usize, usize),
        value: Fr,
        pi: Fr,
    ) -> Self {
        self.gates.push(Gate::new_constant_gate(
            Position::Pos(a.0, a.1),
            Position::Pos(b.0, b.1),
            Position::Pos(c.0, c.1),
            value,
            Some(pi),
        ));
        self
    }

    /// Adds a dummy gate to the circuit.
    pub fn add_dummy_gate(&mut self) {
        self.gates.push(Gate::new_dummy_gate());
    }

    /// Gets the assignment of the circuit.
    pub(crate) fn get_assignment(&self) -> HashMap<&str, Vec<Fr>> {
        let mut result = HashMap::default();
        result.insert(Self::VEC_QL, vec![]);
        result.insert(Self::VEC_QR, vec![]);
        result.insert(Self::VEC_QM, vec![]);
        result.insert(Self::VEC_QO, vec![]);
        result.insert(Self::VEC_QC, vec![]);
        result.insert(Self::VEC_PI, vec![]);

        for gate in &self.gates {
            if gate.is_dummy_gate() {
                continue;
            }
            result.get_mut(Self::VEC_QL).unwrap().push(gate.q_l);
            result.get_mut(Self::VEC_QR).unwrap().push(gate.q_r);
            result.get_mut(Self::VEC_QM).unwrap().push(gate.q_m);
            result.get_mut(Self::VEC_QO).unwrap().push(gate.q_o);
            result.get_mut(Self::VEC_QC).unwrap().push(gate.q_c);
            result.get_mut(Self::VEC_PI).unwrap().push(gate.pi);
        }
        result
    }

    /// Finds the cosets for permutation.
    fn find_cosets(&self, len: usize) -> (Vec<Fr>, Vec<Fr>, Fr, Fr) {
        let domain = GeneralEvaluationDomain::<Fr>::new(len).unwrap();
        let roots = domain.elements().collect::<Vec<_>>();

        let k1 = roots.first().unwrap() + &Fr::one();
        let k2 = k1 + Fr::one();
        let coset1 = roots.iter().map(|root| *root * k1).collect();
        let coset2 = roots.iter().map(|root| *root * k2).collect();

        (coset1, coset2, k1, k2)
    }

    /// Calculates the Copy constraints.
    fn cal_permutation(&self) -> CopyConstraints {
        let len = self.gates.len();
        let domain = GeneralEvaluationDomain::<Fr>::new(len).unwrap();
        let roots = domain.elements().collect::<Vec<_>>();
        let (coset1, coset2, k1, k2) = self.find_cosets(len);

        let mut sigma_1 = roots.clone();
        let mut sigma_2 = coset1.clone();
        let mut sigma_3 = coset2.clone();

        for (index, gate) in self.gates.iter().enumerate() {
            if gate.is_dummy_gate() {
                continue;
            }

            let map_element = |pos: &Position| -> Fr {
                match pos {
                    Position::Pos(i_1, i_2) => {
                        if *i_1 == 0 {
                            roots[*i_2]
                        } else if *i_1 == 1 {
                            coset1[*i_2]
                        } else {
                            coset2[*i_2]
                        }
                    }
                    _ => {
                        todo!()
                    }
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

    /// Pads the circuit with dummy gates to make its size a power of 2.
    fn pad_circuit(mut self) -> Self {
        let len = self.gates.len();
        let exponent = (len - 1).ilog2() + 1;
        let new_len = 1 << exponent;

        for _ in len..new_len {
            self.add_dummy_gate();
        }
        self
    }

    /// Compiles the circuit into a compiled circuit.
    pub fn compile(mut self) -> Result<(GateConstraints, CopyConstraints, usize), String> {
        self = self.pad_circuit();

        let circuit_size = self.gates.len();

        let domain = GeneralEvaluationDomain::<Fr>::new(circuit_size).unwrap();
        let assignment = self.get_assignment();

        let mut interpolated_assignment = assignment
            .into_iter()
            .map(|(k, v)| (k, Evaluations::from_vec_and_domain(v, domain).interpolate()))
            .collect::<HashMap<_, _>>();

        let gate_constraints = GateConstraints::new(
            DensePolynomial::<Fr>::default(),
            DensePolynomial::<Fr>::default(),
            DensePolynomial::<Fr>::default(),
            interpolated_assignment.remove(Self::VEC_QL).unwrap(),
            interpolated_assignment.remove(Self::VEC_QR).unwrap(),
            interpolated_assignment.remove(Self::VEC_QO).unwrap(),
            interpolated_assignment.remove(Self::VEC_QM).unwrap(),
            interpolated_assignment.remove(Self::VEC_QC).unwrap(),
            interpolated_assignment.remove(Self::VEC_PI).unwrap(),
        );

        let copy_constraints = self.cal_permutation();

        Ok((gate_constraints, copy_constraints, circuit_size))
    }

    pub fn get_gates(&self) -> Vec<Gate> {
        self.gates.clone()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;

    use crate::common_preprocessed_input::cpi_circuit::CPICircuit;

    #[test]
    fn create_circuit_test() {
        let parser_circuit = CPICircuit::default()
            .add_multiplication_gate((0, 0), (0, 0), (2, 0), Fr::from(0))
            .add_multiplication_gate((0, 0), (1, 1), (2, 1), Fr::from(0))
            .add_addition_gate((2, 1), (1, 2), (2, 2), Fr::from(0))
            .add_addition_gate((2, 0), (2, 2), (2, 3), Fr::from(0));
        parser_circuit.compile().unwrap();
    }
}

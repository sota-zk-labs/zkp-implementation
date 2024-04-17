use std::collections::HashMap;
use std::{sync::Arc, usize, vec};

use ark_bls12_381::Fr;
use ark_ff::One;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};

use kzg::srs::Srs;

use crate::compiled_circuit::CompiledCircuit;
use crate::constraint::{CopyConstraints, GateConstraints};
use crate::gate::{Gate, Position};

// Represents a circuit consisting of gates and values.
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
    /// Adds an addition gate to the circuit.
    pub fn add_addition_gate(
        mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ) -> Self {
        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        let gate = Gate::new_add_gate(
            Position::Pos(a.0, a.1),
            Position::Pos(b.0, b.1),
            Position::Pos(c.0, c.1),
            Some(pi),
        );
        self.gates.push(gate);
        self
    }

    /// Adds a multiplication gate to the circuit.
    pub fn add_multiplication_gate(
        mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ) -> Self {
        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        let gate = Gate::new_mult_gate(
            Position::Pos(a.0, a.1),
            Position::Pos(b.0, b.1),
            Position::Pos(c.0, c.1),
            Some(pi),
        );
        self.gates.push(gate);
        self
    }

    /// Adds a constant gate to the circuit.
    pub fn add_constant_gate(
        mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ) -> Self {
        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        let gate = Gate::new_constant_gate(
            Position::Pos(a.0, a.1),
            Position::Pos(b.0, b.1),
            Position::Pos(c.0, c.1),
            a.2,
            Some(pi),
        );
        self.gates.push(gate);
        self
    }

    /// Adds a dummy gate to the circuit.
    pub fn add_dummy_gate(&mut self) {
        let gate = Gate::new_dummy_gate();
        self.gates.push(gate);
    }

    /// Gets the assignment of the circuit
    pub(crate) fn get_assignment(&self) -> HashMap<&str, Vec<Fr>> {
        let mut result = HashMap::default();
        result.insert(Self::VEC_A, vec![]);
        result.insert(Self::VEC_B, vec![]);
        result.insert(Self::VEC_C, vec![]);
        result.insert(Self::VEC_QL, vec![]);
        result.insert(Self::VEC_QR, vec![]);
        result.insert(Self::VEC_QM, vec![]);
        result.insert(Self::VEC_QO, vec![]);
        result.insert(Self::VEC_QC, vec![]);
        result.insert(Self::VEC_PI, vec![]);

        for i in 0..self.gates.len() {
            let gate = self.gates.get(i).unwrap();
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

    /// Finds the cosets for permutation.
    fn find_cosets(&self, len: usize) -> (Vec<Fr>, Vec<Fr>, Fr, Fr) {
        let domain = <GeneralEvaluationDomain<Fr>>::new(len).unwrap();
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
        let domain = <GeneralEvaluationDomain<Fr>>::new(len).unwrap();
        let roots = domain.elements().collect::<Vec<_>>();
        let (coset1, coset2, k1, k2) = self.find_cosets(len);

        // create sigma_1, sigma_2, and sigma_3
        let mut sigma_1 = roots.clone();
        let mut sigma_2 = coset1.clone();
        let mut sigma_3 = coset2.clone();

        for (index, gate) in self.gates.iter().enumerate() {
            if gate.is_dummy_gate() {
                continue;
            }

            let map_element = |pos: &Position| {
                let Position::Pos(i_1, i_2) = pos else {
                    todo!()
                };

                if *i_1 == 0 {
                    roots[*i_2]
                } else if *i_1 == 1 {
                    coset1[*i_2]
                } else {
                    coset2[*i_2]
                }
            };

            *sigma_1.get_mut(index).unwrap() = map_element(gate.get_a_wire());
            *sigma_2.get_mut(index).unwrap() = map_element(gate.get_b_wire());
            *sigma_3.get_mut(index).unwrap() = map_element(gate.get_c_wire());
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
        let new_len = 2_usize.pow(exponent);

        for _ in len..new_len {
            self.add_dummy_gate();
        }
        self
    }

    /// Compiles the circuit into a compiled circuit.
    pub fn compile(mut self) -> Result<CompiledCircuit, String> {
        self = self.pad_circuit();

        let circuit_size = self.gates.len();
        let domain = <GeneralEvaluationDomain<Fr>>::new(circuit_size).unwrap();
        let srs = Srs::new(circuit_size);
        let assignment = self.get_assignment();

        let mut interpolated_assignment = assignment
            .into_iter()
            .map(|(k, v)| (k, Evaluations::from_vec_and_domain(v, domain).interpolate()))
            .collect::<HashMap<_, _>>();

        // check the computation of gate constraints
        let roots = domain.elements().collect::<Vec<_>>();
        let w = roots.first().unwrap();
        let tmp = interpolated_assignment
            .get(Self::VEC_A)
            .unwrap()
            .evaluate(w)
            * interpolated_assignment
                .get(Self::VEC_B)
                .unwrap()
                .evaluate(w)
            * interpolated_assignment
                .get(Self::VEC_QM)
                .unwrap()
                .evaluate(w)
            + interpolated_assignment
                .get(Self::VEC_A)
                .unwrap()
                .evaluate(w)
                * interpolated_assignment
                    .get(Self::VEC_QL)
                    .unwrap()
                    .evaluate(w)
            + interpolated_assignment
                .get(Self::VEC_B)
                .unwrap()
                .evaluate(w)
                * interpolated_assignment
                    .get(Self::VEC_QR)
                    .unwrap()
                    .evaluate(w)
            + interpolated_assignment
                .get(Self::VEC_QO)
                .unwrap()
                .evaluate(w)
                * interpolated_assignment
                    .get(Self::VEC_C)
                    .unwrap()
                    .evaluate(w)
            + interpolated_assignment
                .get(Self::VEC_QC)
                .unwrap()
                .evaluate(w)
            + interpolated_assignment
                .get(Self::VEC_PI)
                .unwrap()
                .evaluate(w);
        if tmp != Fr::from(0) {
            return Err("wrong in compute gate constraints".to_string());
        }

        let gate_constraints = GateConstraints::new(
            interpolated_assignment.remove(Self::VEC_A).unwrap(),
            interpolated_assignment.remove(Self::VEC_B).unwrap(),
            interpolated_assignment.remove(Self::VEC_C).unwrap(),
            interpolated_assignment.remove(Self::VEC_QL).unwrap(),
            interpolated_assignment.remove(Self::VEC_QR).unwrap(),
            interpolated_assignment.remove(Self::VEC_QO).unwrap(),
            interpolated_assignment.remove(Self::VEC_QM).unwrap(),
            interpolated_assignment.remove(Self::VEC_QC).unwrap(),
            interpolated_assignment.remove(Self::VEC_PI).unwrap(),
        );

        let copy_constraints = self.cal_permutation();

        Ok(CompiledCircuit::new(
            gate_constraints,
            copy_constraints,
            srs,
            circuit_size,
        ))
    }
}

#[cfg(test)]
#[test]
fn create_circuit_test() {
    let circuit = Circuit::default()
        .add_multiplication_gate(
            (0, 0, Fr::from(1)),
            (0, 0, Fr::from(1)),
            (2, 0, Fr::from(1)),
            Fr::from(0),
        )
        .add_multiplication_gate(
            (0, 0, Fr::from(1)),
            (1, 1, Fr::from(2)),
            (2, 1, Fr::from(2)),
            Fr::from(0),
        )
        .add_addition_gate(
            (2, 1, Fr::from(2)),
            (1, 2, Fr::from(-3)),
            (2, 2, Fr::from(-1)),
            Fr::from(0),
        )
        .add_addition_gate(
            (2, 0, Fr::from(1)),
            (2, 2, Fr::from(-1)),
            (2, 3, Fr::from(0)),
            Fr::from(0),
        );

    assert_eq!(circuit.vals[0][2], circuit.vals[2][1]);
}

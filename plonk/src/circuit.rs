use std::{sync::Arc, usize, vec};

use ark_bls12_381::Fr;
use ark_ff::{Zero, One};
use ark_poly::{domain, EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use crate::CompiledCircuit;
use crate::constrain::{CopyConstraints, GateConstraints};
use crate::errors::CustomError;
use crate::gate::Gate;
use crate::srs::Srs;

struct Circuit {
    gates: Vec<Gate>,
    vals: Vec<Arc<Vec<Fr>>>, 
}

impl Circuit<> {
    pub(crate) fn new() -> Self {
        Self {
            gates: Vec::new(),
            vals: vec![Arc::new(Vec::new()), Arc::new(Vec::new()), Arc::new(Vec::new())]
        }
    }


    pub(crate) fn add_an_add_gate(
        &mut self, 
        a: (usize, usize, Fr), 
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr
    ) -> Result<(), CustomError> {

        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        let gate = Gate::new_add_gate((a.0, a.1), (b.0, b.1), (c.0, c.1), Some(pi));
        self.gates.push(gate);
        Ok(())   
    }

    pub(crate) fn add_a_mult_gate(
        &mut self, 
        a: (usize, usize, Fr), 
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr
    ) -> Result<(), CustomError> {

        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        let gate = Gate::new_mult_gate((a.0, a.1), (b.0, b.1), (c.0, c.1), Some(pi));
        self.gates.push(gate);
        Ok(())   
    }


    pub(crate) fn get_assignment(&self) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>) {

        let len = self.gates.len();
        let mut vec_a = vec![];
        let mut vec_b = vec![];
        let mut vec_c = vec![];
        let mut vec_ql = vec![];
        let mut vec_qr = vec![];
        let mut vec_qm = vec![];
        let mut vec_qo = vec![];
        let mut vec_qc = vec![];
        let mut vec_pi = vec![];

        for (index, gate) in self.gates.iter().enumerate() {
            vec_a.push(self.vals[0][index]);
            vec_b.push(self.vals[1][index]);
            vec_c.push(self.vals[2][index]);
            vec_ql.push(gate.q_l);
            vec_qr.push(gate.q_r);
            vec_qm.push(gate.q_m);
            vec_qo.push(gate.q_o);
            vec_qc.push(gate.q_c);
            vec_pi.push(gate.pi);
        }

        (vec_a, vec_b, vec_c, vec_ql, vec_qr, vec_qm, vec_qo, vec_qc, vec_pi)
    }

    fn find_corset(&self, len: usize) -> (Vec<Fr>, Vec<Fr>) {
        let domain = <GeneralEvaluationDomain<Fr>>::new(len).unwrap();
        let roots = domain.elements().collect::<Vec<_>>();

        let mut k1 = Fr::one();
        while (domain.evaluate_vanishing_polynomial(k1).is_zero()) {
            k1 += Fr::one();
        }

        let mut k2 = k1 + Fr::one();
        while (domain.evaluate_vanishing_polynomial(k2).is_zero()) {
            k2 += Fr::one();
        }

        let mut coset1 = vec![];
        let mut coset2 = vec![];
        for root in roots {
            let cur1 = root * k1;
            let cur2 = root * k2;
            coset1.push(cur1);
            coset2.push(cur2);
        }

        (coset1, coset2)

    }

    fn make_permutation(&self) -> CopyConstraints {
        let len = self.gates.len();
        let domain = <GeneralEvaluationDomain<Fr>>::new(len).unwrap();
        let roots = domain.elements().collect::<Vec<_>>();
        let (coset1, coset2) = self.find_corset(len);

        /// create sigma_1, sigma_2, and sigma_3
        let mut sigma_1 = vec![];
        let mut sigma_2 = vec![];
        let mut sigma_3 = vec![];

        for gate in self.gates {
            let (i_1, i_2) = gate.get_a_wire();
            if (i_1 == 0) {
                sigma_1.push(roots[i_2].clone());
            } else if (i_1 == 1) {
                sigma_1.push(coset1[i_2].clone());
            } else {
                sigma_1.push(coset2[i_2].clone());
            }

            let (i_1, i_2) = gate.get_b_wire();
            if (i_1 == 0) {
                sigma_2.push(roots[i_2].clone());
            } else if (i_1 == 1) {
                sigma_2.push(coset1[i_2].clone());
            } else {
                sigma_2.push(coset2[i_2].clone());
            }

            let (i_1, i_2) = gate.get_c_wire();
            if (i_1 == 0) {
                sigma_3.push(roots[i_2].clone());
            } else if (i_1 == 1) {
                sigma_3.push(coset1[i_2].clone());
            } else {
                sigma_3.push(coset2[i_2].clone());
            }
        }

        let s_sigma_1 = Evaluations::from_vec_and_domain(sigma_1, domain).interpolate();
        let s_sigma_2 = Evaluations::from_vec_and_domain(sigma_2, domain).interpolate();
        let s_sigma_3 = Evaluations::from_vec_and_domain(sigma_3, domain).interpolate();

        CopyConstraints::new(
            s_sigma_1,
            s_sigma_2,
            s_sigma_3
        )
    }

    pub(crate) fn compile_circuit(&self) -> CompiledCircuit {
        let len = self.gates.len();
        let domain = <GeneralEvaluationDomain<Fr>>::new(len).unwrap();
        let srs = Srs::random(domain.size());
        let (vec_a, vec_b, vec_c, vec_ql, vec_qr, vec_qm, vec_qo, vec_qc, vec_pi) = self.get_assignment();

        let gate_constraints = GateConstraints::new(
            Evaluations::from_vec_and_domain(vec_a, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_b, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_c, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_ql, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_qr, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_qm, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_qo, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_qc, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_pi, domain).interpolate()
        );

        let copy_constraints = self.make_permutation();

        CompiledCircuit::new(gate_constraints, copy_constraints, srs, domain, len)


    }



}

#[cfg(test)]

#[test]
fn create_circuit_test() {
    let mut circuit = Circuit::new();
    circuit.add_a_mult_gate((0,0,Fr::from(1)), (0,0,Fr::from(1)), (2,0,Fr::from(1)), Fr::from(0));
    circuit.add_a_mult_gate((0,0,Fr::from(1)), (1,1,Fr::from(2)), (2,1,Fr::from(2)), Fr::from(0));
    circuit.add_an_add_gate((2,1,Fr::from(2)), (1,2,Fr::from(-3)), (2,2,Fr::from(-1)), Fr::from(0));
    circuit.add_an_add_gate((2,0,Fr::from(1)), (2,2,Fr::from(-1)), (2,3,Fr::from(0)), Fr::from(0));
    println!("Len: {}", circuit.gates.len());
    for i in 0..3 {
        println!("value in vec {} are:  {:?}", i, circuit.vals[i]);
    }

    println!("{:?} = {:?}", circuit.vals[0][2], circuit.vals[2][1]);

    assert_eq!(circuit.vals[0][2], circuit.vals[2][1]);
}

#[test]
fn circuit_test() {
    let mut circuit = Circuit::new();
    circuit.add_a_mult_gate((0,0,Fr::from(1)), (0,0,Fr::from(1)), (2,0,Fr::from(1)), Fr::from(0));
    circuit.add_a_mult_gate((0,0,Fr::from(1)), (1,1,Fr::from(2)), (2,1,Fr::from(2)), Fr::from(0));
    circuit.add_an_add_gate((2,1,Fr::from(2)), (1,2,Fr::from(-3)), (2,2,Fr::from(-1)), Fr::from(0));
    circuit.add_an_add_gate((2,0,Fr::from(1)), (2,2,Fr::from(-1)), (2,3,Fr::from(0)), Fr::from(0));
    println!("Len: {}", circuit.gates.len());
    for i in 0..3 {
        println!("value in vec {} are:  {:?}", i, circuit.vals[i]);
    }

    println!("{:?} = {:?}", circuit.vals[0][2], circuit.vals[2][1]);

    assert_eq!(circuit.vals[0][0], circuit.vals[1][0]);
}
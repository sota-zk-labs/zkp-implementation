use std::{sync::Arc, usize, vec};

use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};

use kzg::srs::Srs;

use crate::CompiledCircuit;
use crate::constrain::{CopyConstraints, GateConstraints};
use crate::gate::{Gate, Position};

#[allow(dead_code)]
pub struct Circuit {
    gates: Vec<Gate>,
    vals: Vec<Arc<Vec<Fr>>>,
}

#[allow(dead_code)]
impl Circuit<> {
    pub fn new() -> Self {
        Self {
            gates: Vec::new(),
            vals: vec![Arc::new(Vec::new()), Arc::new(Vec::new()), Arc::new(Vec::new())],
        }
    }

    pub fn add_an_add_gate(
        &mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ) {
        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        let gate = Gate::new_add_gate(Position::Pos(a.0, a.1), Position::Pos(b.0, b.1), Position::Pos(c.0, c.1), Some(pi));
        self.gates.push(gate);
    }

    pub fn add_a_mult_gate(
        &mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ){
        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        let gate = Gate::new_mult_gate(Position::Pos(a.0, a.1), Position::Pos(b.0, b.1), Position::Pos(c.0, c.1), Some(pi));
        self.gates.push(gate);
    }

    pub fn add_a_constant_gate(
        &mut self,
        a: (usize, usize, Fr),
        b: (usize, usize, Fr),
        c: (usize, usize, Fr),
        pi: Fr,
    ) {
        Arc::get_mut(&mut self.vals[0]).unwrap().push(a.2);
        Arc::get_mut(&mut self.vals[1]).unwrap().push(b.2);
        Arc::get_mut(&mut self.vals[2]).unwrap().push(c.2);

        let gate = Gate::new_constant_gate(Position::Pos(a.0, a.1), Position::Pos(b.0, b.1), Position::Pos(c.0, c.1), a.2, Some(pi));
        self.gates.push(gate);
    }

    pub fn add_a_dummy_gate(&mut self) {
        let gate = Gate::new_dummy_gate();
        self.gates.push(gate);
    }


    pub(crate) fn get_assignment(&self) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>) {
        let mut vec_a = vec![];
        let mut vec_b = vec![];
        let mut vec_c = vec![];
        let mut vec_ql = vec![];
        let mut vec_qr = vec![];
        let mut vec_qm = vec![];
        let mut vec_qo = vec![];
        let mut vec_qc = vec![];
        let mut vec_pi = vec![];

        for i in 0..self.gates.len() {
            let gate = self.gates.get(i).unwrap();
            if *gate.get_a_wire() == Position::Dummy {
                continue;
            } else {
                vec_a.push(self.vals[0][i]);
                vec_b.push(self.vals[1][i]);
                vec_c.push(self.vals[2][i]);
                vec_ql.push(gate.q_l);
                vec_qr.push(gate.q_r);
                vec_qm.push(gate.q_m);
                vec_qo.push(gate.q_o);
                vec_qc.push(gate.q_c);
                vec_pi.push(gate.pi);
            }
        }


        (vec_a, vec_b, vec_c, vec_ql, vec_qr, vec_qm, vec_qo, vec_qc, vec_pi)
    }

    fn find_coset(&self, len: usize) -> (Vec<Fr>, Vec<Fr>, Fr, Fr) {
        let domain = <GeneralEvaluationDomain<Fr>>::new(len).unwrap();
        let roots = domain.elements().collect::<Vec<_>>();

        let mut k1 = Fr::one();
        while domain.evaluate_vanishing_polynomial(k1).is_zero() {
            k1 += Fr::one();
        }

        let mut k2 = k1 + Fr::one();
        while domain.evaluate_vanishing_polynomial(k2).is_zero() {
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

        (coset1, coset2, k1, k2)
    }

    fn make_permutation(&self) -> CopyConstraints {
        let len = self.gates.len();
        let domain = <GeneralEvaluationDomain<Fr>>::new(len).unwrap();
        let roots = domain.elements().collect::<Vec<_>>();
        let (coset1, coset2, k1, k2) = self.find_coset(len);

        // create sigma_1, sigma_2, and sigma_3
        let mut sigma_1 = vec![];
        let mut sigma_2 = vec![];
        let mut sigma_3 = vec![];

        for (index, gate) in self.gates.iter().enumerate() {
            if *gate.get_a_wire() == Position::Dummy {
                sigma_1.push(roots[index].clone());
                sigma_2.push(coset1[index].clone());
                sigma_3.push(coset2[index].clone());
                continue;
            }
            let Position::Pos(i_1, i_2) = gate.get_a_wire() else { todo!() };
            // println!("wireA: i1: {:?}, i2: {:?}", i_1, i_2);
            if *i_1 == 0 {
                sigma_1.push(roots[*i_2].clone());
            } else if *i_1 == 1 {
                sigma_1.push(coset1[*i_2].clone());
            } else {
                sigma_1.push(coset2[*i_2].clone());
            }

            let Position::Pos(i_1, i_2) = gate.get_b_wire() else { todo!() };
            if *i_1 == 0 {
                sigma_2.push(roots[*i_2].clone());
            } else if *i_1 == 1 {
                sigma_2.push(coset1[*i_2].clone());
            } else {
                sigma_2.push(coset2[*i_2].clone());
            }

            let Position::Pos(i_1, i_2) = gate.get_c_wire() else { todo!() };
            if *i_1 == 0 {
                sigma_3.push(roots[*i_2].clone());
            } else if *i_1 == 1 {
                sigma_3.push(coset1[*i_2].clone());
            } else {
                sigma_3.push(coset2[*i_2].clone());
            }
        }


        let s_sigma_1 = Evaluations::from_vec_and_domain(sigma_1, domain).interpolate();
        let s_sigma_2 = Evaluations::from_vec_and_domain(sigma_2, domain).interpolate();
        let s_sigma_3 = Evaluations::from_vec_and_domain(sigma_3, domain).interpolate();

        CopyConstraints::new(
            s_sigma_1,
            s_sigma_2,
            s_sigma_3,
            k1,
            k2,
        )
    }

    fn fill_circuit(&mut self) {
        let len = self.gates.len();

        let exponent = (len - 1).ilog2() + 1;
        let new_len = 2_usize.pow(exponent);

        for _ in len..new_len {
            let _ = self.add_a_dummy_gate();
        }
    }

    pub fn compile_circuit(&mut self) -> CompiledCircuit {
        self.fill_circuit();
        let len = self.gates.len();
        let domain = <GeneralEvaluationDomain<Fr>>::new(len).unwrap();
        let srs = Srs::random(domain.size());
        let (vec_a, vec_b, vec_c, vec_ql, vec_qr, vec_qm, vec_qo, vec_qc, vec_pi) = self.get_assignment();


        let roots = domain.elements().collect::<Vec<_>>();

        let a_x = Evaluations::from_vec_and_domain(vec_a.clone(), domain).interpolate();
        let b_x = Evaluations::from_vec_and_domain(vec_b.clone(), domain).interpolate();
        let c_x = Evaluations::from_vec_and_domain(vec_c.clone(), domain).interpolate();
        let ql_x = Evaluations::from_vec_and_domain(vec_ql.clone(), domain).interpolate();
        let qr_x = Evaluations::from_vec_and_domain(vec_qr.clone(), domain).interpolate();
        let qm_x = Evaluations::from_vec_and_domain(vec_qm.clone(), domain).interpolate();
        let qo_x = Evaluations::from_vec_and_domain(vec_qo.clone(), domain).interpolate();
        let qc_x = Evaluations::from_vec_and_domain(vec_qc.clone(), domain).interpolate();
        let pi_x = Evaluations::from_vec_and_domain(vec_pi.clone(), domain).interpolate();

        // check
        {
            let w = roots.get(1).unwrap();
            let tmp = a_x.evaluate(w) * b_x.evaluate(w) * qm_x.evaluate(w) + a_x.evaluate(w) * ql_x.evaluate(w)
                + b_x.evaluate(w) * qr_x.evaluate(w) + qo_x.evaluate(w) * c_x.evaluate(w) + qc_x.evaluate(w) + pi_x.evaluate(w);
            assert_eq!(tmp, Fr::from(0), "Wrong in compute gate constraints");
        }

        let gate_constraints = GateConstraints::new(
            Evaluations::from_vec_and_domain(vec_a, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_b, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_c, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_ql, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_qr, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_qo, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_qm, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_qc, domain).interpolate(),
            Evaluations::from_vec_and_domain(vec_pi, domain).interpolate(),
        );

        let copy_constraints = self.make_permutation();

        CompiledCircuit::new(gate_constraints, copy_constraints, srs, domain, len)
    }
}

#[cfg(test)]
#[test]
fn create_circuit_test() {
    let mut circuit = Circuit::new();
    let _ = circuit.add_a_mult_gate((0, 0, Fr::from(1)), (0, 0, Fr::from(1)), (2, 0, Fr::from(1)), Fr::from(0));
    let _ = circuit.add_a_mult_gate((0, 0, Fr::from(1)), (1, 1, Fr::from(2)), (2, 1, Fr::from(2)), Fr::from(0));
    let _ = circuit.add_an_add_gate((2, 1, Fr::from(2)), (1, 2, Fr::from(-3)), (2, 2, Fr::from(-1)), Fr::from(0));
    let _ = circuit.add_an_add_gate((2, 0, Fr::from(1)), (2, 2, Fr::from(-1)), (2, 3, Fr::from(0)), Fr::from(0));

    assert_eq!(circuit.vals[0][2], circuit.vals[2][1]);
}


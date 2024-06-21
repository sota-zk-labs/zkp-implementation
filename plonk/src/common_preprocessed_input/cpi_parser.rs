use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use ark_bls12_381::Fr;
use ark_poly::univariate::DensePolynomial;

use kzg::commitment::KzgCommitment;
use kzg::scheme::KzgScheme;

use crate::common_preprocessed_input::cpi_circuit::CPICircuit;
use crate::common_preprocessed_input::cpi_parser::TypeOfCircuit::Multiplication;
use crate::constraint::{CopyConstraints, GateConstraints};

/// Enum defining the type of circuit gate
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum TypeOfCircuit {
    Addition,
    Multiplication,
    Constant,
}

/// Structure representing a gate in the parser
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct ParserGate {
    left: ParserWire,
    right: ParserWire,
    bottom: ParserWire,
    type_of_circuit: TypeOfCircuit,
}

impl ParserGate {
    fn new(
        left: ParserWire,
        right: ParserWire,
        bottom: ParserWire,
        type_of_circuit: TypeOfCircuit,
    ) -> Self {
        ParserGate {
            left,
            right,
            bottom,
            type_of_circuit,
        }
    }
}

/// Structure representing a wire in the parser
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct ParserWire {
    value_string: String,
}

impl ParserWire {
    fn new(value_string: String) -> Self {
        ParserWire { value_string }
    }
}

/// Structure representing the common preprocessed input
pub struct CommonPreprocessedInput {
    pub n: usize,
    pub k1: Fr,
    pub k2: Fr,
    pub com_q_lx: KzgCommitment,
    pub com_q_rx: KzgCommitment,
    pub com_q_mx: KzgCommitment,
    pub com_q_ox: KzgCommitment,
    pub com_q_cx: KzgCommitment,
    pub com_s_sigma_1: KzgCommitment,
    pub com_s_sigma_2: KzgCommitment,
    pub com_s_sigma_3: KzgCommitment,
    pub pi_x: DensePolynomial<Fr>,
}

impl CommonPreprocessedInput {
    pub fn new(
        compiled_circuit: (GateConstraints, CopyConstraints, usize),
        scheme: KzgScheme,
    ) -> Self {
        let copy_constraint = compiled_circuit.1;
        let gate_constraint = compiled_circuit.0;

        let com_q_mx = scheme.commit(gate_constraint.q_mx());
        let com_q_lx = scheme.commit(gate_constraint.q_lx());
        let com_q_rx = scheme.commit(gate_constraint.q_rx());
        let com_q_ox = scheme.commit(gate_constraint.q_ox());
        let com_q_cx = scheme.commit(gate_constraint.q_cx());
        let com_s_sigma_1 = scheme.commit(copy_constraint.s_sigma_1());
        let com_s_sigma_2 = scheme.commit(copy_constraint.s_sigma_2());
        let com_s_sigma_3 = scheme.commit(copy_constraint.s_sigma_3());

        Self {
            n: compiled_circuit.2,
            k1: *copy_constraint.k1(),
            k2: *copy_constraint.k2(),
            com_q_lx,
            com_q_rx,
            com_q_mx,
            com_q_ox,
            com_q_cx,
            com_s_sigma_1,
            com_s_sigma_2,
            com_s_sigma_3,
            pi_x: gate_constraint.pi_x().clone(),
        }
    }
}

/// Parser for converting string input to common preprocessed input
#[derive(Default)]
pub struct CPIGenerator {}

impl CPIGenerator {
    /// Compute common preprocessed input from string input
    pub fn compute_common_preprocessed_input(
        self,
        input: &str,
        scheme: KzgScheme,
    ) -> Result<CommonPreprocessedInput, String> {
        let input = Self::normalize(input);
        let (gate_list, position_map) = self.prepare_generation(&input);
        let circuit = Self::gen_circuit(gate_list, position_map);
        Ok(CommonPreprocessedInput::new(circuit.compile()?, scheme))
    }

    /// Prepare generation of gates and position map
    fn prepare_generation(
        &self,
        string: &str,
    ) -> (Vec<ParserGate>, HashMap<String, Vec<(usize, usize)>>) {
        let gate_list: RefCell<Vec<ParserGate>> = RefCell::new(Vec::new());
        let gate_set: RefCell<HashSet<ParserGate>> = RefCell::new(HashSet::new());
        let position_map: RefCell<HashMap<String, Vec<(usize, usize)>>> =
            RefCell::new(HashMap::new());

        let result = string
            .split('=')
            .map(|s| s.to_string())
            .collect::<Vec<String>>();
        assert_eq!(result.len(), 2);
        let string = result[0].clone();
        let result = result[1].clone();

        let mut split_list: Vec<String> = string.split('+').map(|s| s.to_string()).collect();
        split_list.push("-".to_string() + result.as_str());
        split_list
            .into_iter()
            .map(|split_list| {
                split_list
                    .split('*')
                    .map(|s| s.trim().to_string())
                    .map(|s| {
                        self.check_constant(
                            &mut gate_list.borrow_mut(),
                            &mut gate_set.borrow_mut(),
                            &mut position_map.borrow_mut(),
                            s.clone(),
                        );
                        ParserWire::new(s.clone())
                    })
                    .collect::<Vec<ParserWire>>()
            })
            .map(|multi_collections| {
                let mut gate_list = gate_list.borrow_mut();
                let mut gate_set = gate_set.borrow_mut();
                let mut position_map = position_map.borrow_mut();
                multi_collections
                    .into_iter()
                    .reduce(|left, right| {
                        let gate_number = gate_list.len();
                        let result = ParserWire::new(
                            format!("{}*{}", &left.value_string, &right.value_string),
                            // left.value_fr * right.value_fr,
                        );
                        let gate = ParserGate::new(
                            left.clone(),
                            right.clone(),
                            result.clone(),
                            Multiplication,
                        );
                        if gate_set.get(&gate).is_some() {
                            return result;
                        }
                        gate_list.push(gate.clone());
                        gate_set.insert(gate);

                        Self::push_into_position_map_or_insert(
                            0,
                            gate_number,
                            &mut position_map,
                            &left.value_string,
                        );
                        Self::push_into_position_map_or_insert(
                            1,
                            gate_number,
                            &mut position_map,
                            &right.value_string,
                        );
                        Self::push_into_position_map_or_insert(
                            2,
                            gate_number,
                            &mut position_map,
                            &result.value_string,
                        );
                        result
                    })
                    .unwrap()
            })
            .reduce(|pre, cur| {
                let mut gate_list = gate_list.borrow_mut();
                let mut gate_set = gate_set.borrow_mut();
                let mut position_map = position_map.borrow_mut();
                self.generate_additional_gate(
                    &mut gate_list,
                    &mut gate_set,
                    &mut position_map,
                    pre,
                    cur,
                )
            });

        (gate_list.take(), position_map.take())
    }

    /// Generate the circuit with gates and position map
    fn gen_circuit(
        gate_list: Vec<ParserGate>,
        position_map: HashMap<String, Vec<(usize, usize)>>,
    ) -> CPICircuit {
        let mut result = CPICircuit::default();
        let mut position_map = position_map
            .into_iter()
            .map(|(key, mut vec)| {
                vec.reverse();
                vec.rotate_right(1);
                (key, vec)
            })
            .collect::<HashMap<String, Vec<(usize, usize)>>>();

        for gate in gate_list.iter() {
            let left = position_map
                .get_mut(&gate.left.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let left = (left.0, left.1);
            let right = position_map
                .get_mut(&gate.right.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let right = (right.0, right.1);
            let bottom = position_map
                .get_mut(&gate.bottom.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let bottom = (bottom.0, bottom.1);
            match &gate.type_of_circuit {
                TypeOfCircuit::Addition => {
                    result = result.add_addition_gate(left, right, bottom, Fr::from(0));
                }
                TypeOfCircuit::Multiplication => {
                    result = result.add_multiplication_gate(left, right, bottom, Fr::from(0));
                }
                TypeOfCircuit::Constant => {
                    result = result.add_constant_gate(
                        left,
                        right,
                        bottom,
                        Fr::from(gate.left.value_string.parse::<i32>().unwrap()),
                        Fr::from(0),
                    );
                }
            }
        }
        result
    }
    /// Generate an additional gate
    fn generate_additional_gate(
        &self,
        gate_list: &mut Vec<ParserGate>,
        gate_set: &mut HashSet<ParserGate>,
        position_map: &mut HashMap<String, Vec<(usize, usize)>>,
        left: ParserWire,
        right: ParserWire,
    ) -> ParserWire {
        let gate_number = gate_list.len();
        let result = ParserWire::new(format!("{}+{}", &left.value_string, &right.value_string));
        let gate = ParserGate::new(
            left.clone(),
            right.clone(),
            result.clone(),
            TypeOfCircuit::Addition,
        );

        if gate_set.get(&gate).is_some() {
            return result;
        }

        gate_list.push(gate.clone());
        gate_set.insert(gate);

        Self::push_into_position_map_or_insert(0, gate_number, position_map, &left.value_string);
        Self::push_into_position_map_or_insert(1, gate_number, position_map, &right.value_string);
        Self::push_into_position_map_or_insert(2, gate_number, position_map, &result.value_string);
        result
    }

    /// Generate a constant gate
    fn generate_constant_gate(
        &self,
        gate_list: &mut Vec<ParserGate>,
        gate_set: &mut HashSet<ParserGate>,
        position_map: &mut HashMap<String, Vec<(usize, usize)>>,
        value: ParserWire,
    ) -> ParserWire {
        let gate_number = gate_list.len();
        let right = ParserWire::new("0".to_string());
        let result = ParserWire::new(format!("{}+{}", &value.value_string, "0"));
        let gate = ParserGate::new(
            value.clone(),
            right.clone(),
            result.clone(),
            TypeOfCircuit::Constant,
        );

        if gate_set.get(&gate).is_some() {
            return result;
        }

        gate_list.push(gate.clone());
        gate_set.insert(gate);

        Self::push_into_position_map_or_insert(0, gate_number, position_map, &value.value_string);
        Self::push_into_position_map_or_insert(1, gate_number, position_map, "0");
        Self::push_into_position_map_or_insert(2, gate_number, position_map, &result.value_string);
        result
    }

    /// Check if the value represents a constant and generate a constant gate if so
    fn check_constant(
        &self,
        gate_list: &mut Vec<ParserGate>,
        gate_set: &mut HashSet<ParserGate>,
        position_map: &mut HashMap<String, Vec<(usize, usize)>>,
        value: String,
    ) {
        if value.parse::<i32>().is_ok() {
            self.generate_constant_gate(gate_list, gate_set, position_map, ParserWire::new(value));
        };
    }

    /// Insert a wire position pair into the position map
    fn push_into_position_map_or_insert(
        wire_number: usize,
        gate_number: usize,
        position_map: &mut HashMap<String, Vec<(usize, usize)>>,
        value: &str,
    ) {
        let var_exist = position_map.get(value).is_some();
        if var_exist {
            position_map
                .get_mut(value)
                .expect("var_exist guaranty its existence")
                .push((wire_number, gate_number))
        } else {
            position_map.insert(value.to_string(), vec![(wire_number, gate_number)]);
        }
    }

    /// Normalize the polynomial string to be compatible with the parser
    ///
    /// Feature:
    /// - Lower case
    /// - Expand simple ^ into *
    /// - Delete space character " "
    fn normalize(string: &str) -> String {
        let string = string.to_lowercase();
        let mut result = String::new();
        let mut last_char = ' ';
        let mut number_buffer = String::new();
        let mut flag = false;
        for char in string.chars() {
            if char == ' ' {
                continue;
            }
            if char == '^' {
                flag = true;
            } else if !char.is_numeric() {
                if flag {
                    if !number_buffer.is_empty() {
                        for _ in 0..number_buffer.parse::<i32>().unwrap() - 1 {
                            result.push('*');
                            result.push(last_char);
                        }
                        flag = false;
                    } else {
                        panic!("can't parse polynomial")
                    }
                }
                last_char = char;
                result.push(char);
                number_buffer = String::new();
            } else {
                number_buffer.push(char);
                if !flag {
                    last_char = char;
                    result.push(char);
                }
            }
        }
        if flag && !number_buffer.is_empty() {
            for _ in 0..number_buffer.parse::<i32>().unwrap() - 1 {
                result.push('*');
                result.push(last_char);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::common_preprocessed_input::cpi_parser::CPIGenerator;
    use crate::parser::Parser;
    use ark_bls12_381::Fr;
    use kzg::scheme::KzgScheme;
    use kzg::srs::Srs;

    /// Test generated circuit with prover circuit
    #[test]
    fn parser_prover_test() {
        let str = "x*y+3*x^2+x*y*z=11";

        let srs = Srs::new(20);

        let scheme = KzgScheme::new(srs.clone());
        let scheme1 = KzgScheme::new(srs.clone());
        // Common preprocessed input parser
        let cpi = CPIGenerator::default()
            .compute_common_preprocessed_input(str, scheme)
            .unwrap();

        // Prover parser
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(1));
        parser.add_witness("y", Fr::from(2));
        parser.add_witness("z", Fr::from(3));
        let compiled_circuit = parser.parse(str).compile().unwrap();
        let copy_constraint = compiled_circuit.copy_constraints();
        let gate_constraint = compiled_circuit.gate_constraints();

        assert_eq!(cpi.n, compiled_circuit.size);
        assert_eq!(cpi.k1, copy_constraint.k1().clone());
        assert_eq!(cpi.k2, copy_constraint.k2().clone());
        assert_eq!(
            cpi.com_q_lx,
            scheme1.commit(&gate_constraint.q_lx().clone())
        );
        assert_eq!(
            cpi.com_q_rx,
            scheme1.commit(&gate_constraint.q_rx().clone())
        );
        assert_eq!(
            cpi.com_q_mx,
            scheme1.commit(&gate_constraint.q_mx().clone())
        );
        assert_eq!(
            cpi.com_q_ox,
            scheme1.commit(&gate_constraint.q_ox().clone())
        );
        assert_eq!(
            cpi.com_q_cx,
            scheme1.commit(&gate_constraint.q_cx().clone())
        );
        assert_eq!(
            cpi.com_s_sigma_1,
            scheme1.commit(&copy_constraint.s_sigma_1().clone())
        );
        assert_eq!(
            cpi.com_s_sigma_2,
            scheme1.commit(&copy_constraint.s_sigma_2().clone())
        );
        assert_eq!(
            cpi.com_s_sigma_3,
            scheme1.commit(&copy_constraint.s_sigma_3().clone())
        );
        assert_eq!(cpi.pi_x, gate_constraint.pi_x().clone());
    }
}

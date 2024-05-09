use crate::circuit::Circuit;
use crate::parser::TypeOfCircuit::*;
use ark_bls12_381::Fr;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Neg;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum TypeOfCircuit {
    Addition,
    Multiplication,
    Constant,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct Gate {
    //Left branch of the circuit
    pub left: Wire,
    //Right branch of the circuit
    pub right: Wire,
    //Bottom part (result) of the circuit
    pub bottom: Wire,
    // type 0: add, type 1: mul, type 2: const
    pub type_of_circuit: TypeOfCircuit,
}

impl Gate {
    fn new(left: Wire, right: Wire, bottom: Wire, type_of_circuit: TypeOfCircuit) -> Self {
        Gate {
            left,
            right,
            bottom,
            type_of_circuit,
        }
    }

    /// Change the result value of this gate
    pub fn change_result(&mut self, value: Fr) {
        self.bottom.value_fr = value
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct Wire {
    value_string: String,
    value_fr: Fr,
}

impl Wire {
    fn new(value_string: String, value_fr: Fr) -> Self {
        Wire {
            value_string,
            value_fr,
        }
    }
}

/// String to circuit parser
///
/// See parse function for usage
#[derive(Default)]
pub struct Parser {
    pub witnesses: HashMap<String, Fr>,
}

impl Parser {
    /// Add witness for the polynomial string
    ///
    /// ```
    /// use ark_bls12_381::Fr;
    /// use plonk::parser::Parser;
    ///
    /// let mut parser = Parser::default();
    /// parser.add_witness("x", Fr::from(1));
    ///
    /// parser.parse("x=1");
    /// ```
    pub fn add_witness(&mut self, variable: &str, value: Fr) {
        self.witnesses.insert(variable.to_string(), value);
    }

    /// Parse string into circuit
    ///
    /// ```
    /// use ark_bls12_381::Fr;
    /// use sha2::Sha256;
    /// use plonk::parser::Parser;
    /// use plonk::{prover, verifier};
    /// let mut parser = Parser::default();
    /// parser.add_witness("x", Fr::from(1));
    /// parser.add_witness("y", Fr::from(2));
    /// parser.add_witness("z", Fr::from(3));
    /// let compiled_circuit = parser
    ///     .parse("x*y+3*x*x+x*y*z=11")
    ///     .compile()
    ///     .unwrap();
    ///
    /// let proof = prover::generate_proof::<Sha256>(&compiled_circuit);
    ///
    /// assert!(verifier::verify::<Sha256>(&compiled_circuit, proof).is_ok());
    /// ```
    pub fn parse(self, input: &str) -> Circuit {
        let input = Self::parse_string(input);
        let input = &input;

        //Step 1: prepare gate_list and position_map prior to coordinate pair accumulator
        let (gate_list, position_map) = self.prepare_gen_circuit(input);

        //Step 2: generate the actual circuit with coordinate pair accumulator for copy constraint
        Self::gen_circuit(gate_list, position_map)
    }

    /// Generate [gate_list] and [position_map] to prepare for coordinate pair accumulator
    fn prepare_gen_circuit(
        &self,
        string: &str,
    ) -> (Vec<Gate>, HashMap<String, Vec<(usize, usize)>>) {
        let gate_list: RefCell<Vec<Gate>> = RefCell::new(Vec::new());
        let gate_set: RefCell<HashSet<Gate>> = RefCell::new(HashSet::new());
        //Map of integer key will be here, it will then be inserted into gen circuit method
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
                    .map(|s| Wire::new(s.clone(), self.get_witness_value(&s)))
                    .collect::<Vec<Wire>>()
            })
            .map(|multi_collections| {
                let mut gate_list = gate_list.borrow_mut();
                let mut gate_set = gate_set.borrow_mut();
                let mut position_map = position_map.borrow_mut();
                multi_collections
                    .into_iter()
                    .reduce(|left, right| {
                        let gate_number = gate_list.len();
                        let result = Wire::new(
                            format!("{}*{}", &left.value_string, &right.value_string),
                            left.value_fr * right.value_fr,
                        );
                        let gate =
                            Gate::new(left.clone(), right.clone(), result.clone(), Multiplication);
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

        gate_list
            .borrow_mut()
            .last_mut()
            .unwrap()
            .change_result(Fr::from(0));

        (gate_list.take(), position_map.take())
    }

    /// Generate the circuit with a [gate_list] and [position_map] to coordinate pair accumulator for copy constraint
    fn gen_circuit(
        gate_list: Vec<Gate>,
        position_map: HashMap<String, Vec<(usize, usize)>>,
    ) -> Circuit {
        let mut result = Circuit::default();
        let mut position_map = position_map
            .into_iter()
            .map(|(key, mut vec)| {
                vec.reverse();
                vec.rotate_right(1);
                (key, vec)
            })
            .collect::<HashMap<String, Vec<(usize, usize)>>>();
        for gate in gate_list.iter() {
            #[cfg(test)]
            println!("{:?}", gate);
            let left = position_map
                .get_mut(&gate.left.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let left = (left.0, left.1, Fr::from(gate.left.value_fr));
            let right = position_map
                .get_mut(&gate.right.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let right = (right.0, right.1, Fr::from(gate.right.value_fr));
            let bottom = position_map
                .get_mut(&gate.bottom.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let bottom = (bottom.0, bottom.1, Fr::from(gate.bottom.value_fr));
            match gate.type_of_circuit {
                Addition => {
                    result = result.add_addition_gate(left, right, bottom, Fr::from(0));
                }
                Multiplication => {
                    result = result.add_multiplication_gate(left, right, bottom, Fr::from(0));
                }
                Constant => {
                    result = result.add_constant_gate(left, right, bottom, Fr::from(0));
                }
            }
            #[cfg(test)]
            println!("{:?} {:?} {:?}", left, right, bottom);
        }
        result
    }

    /// Generate additional gate
    ///
    /// Take in [left] and [right] as corresponding wire and output result wire
    fn generate_additional_gate(
        &self,
        gate_list: &mut Vec<Gate>,
        gate_set: &mut HashSet<Gate>,
        position_map: &mut HashMap<String, Vec<(usize, usize)>>,
        left: Wire,
        right: Wire,
    ) -> Wire {
        let gate_number = gate_list.len();
        let result = Wire::new(
            format!("{}+{}", &left.value_string, &right.value_string),
            left.value_fr + right.value_fr,
        );
        let gate = Gate::new(left.clone(), right.clone(), result.clone(), Addition);
        //if this gate already exist, skip this move
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

    /// Get the value of [value] in Fr
    fn get_witness_value(&self, mut value: &str) -> Fr {
        let mut is_negative = false;
        if &value[..1] == "-" {
            is_negative = true;
            value = &value[1..];
        }
        let result = match self.witnesses.get(value) {
            //Not a constant, search in map
            Some(value) => *value,
            //Value is a constant insert a constant gate
            None => Fr::from(value.parse::<i32>().unwrap()),
        };
        if is_negative {
            result.neg()
        } else {
            result
        }
    }

    /// Insert a pair of (x, y) corresponding to [wire_number] and [gate_number] into [position_map] by checking if it exists in the map or not
    //TODO: it could have been try_insert() or something but i think it should be in a wrapper instead
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

    /// Parse a polynomial string to be compatible with parser
    ///
    /// Feature:
    /// - Lower case
    /// - Expand simple ^ into *
    /// - Delete space character " "
    fn parse_string(string: &str) -> String {
        let string = string.to_lowercase();
        let mut result = String::new();
        let mut last_char = ' ';
        let mut flag = false;
        for char in string.chars() {
            if char == ' ' {
                continue;
            }
            if char == '^' {
                flag = true;
            } else if flag {
                if char.is_numeric() {
                    for _ in 0..char.to_string().parse::<i32>().unwrap() - 1 {
                        result.push('*');
                        result.push(last_char);
                    }
                    flag = false;
                } else {
                    panic!("can't parse polynomial")
                }
            } else {
                last_char = char;
                result.push(char);
            }
        }
        result
    }
}

//TODO: implement / operator

#[cfg(test)]
mod tests {
    use crate::circuit::Circuit;
    use crate::parser::Parser;
    use crate::{prover, verifier};
    use ark_bls12_381::Fr;
    use sha2::Sha256;

    /// Test generated circuit with prover
    #[test]
    fn parser_prover_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(1));
        parser.add_witness("y", Fr::from(2));
        parser.add_witness("z", Fr::from(3));
        let compiled_circuit = parser.parse("x*y+3*x^2+x*y*z=11").compile().unwrap();

        let proof = prover::generate_proof::<Sha256>(&compiled_circuit);

        assert!(verifier::verify::<Sha256>(&compiled_circuit, proof).is_ok());
    }

    /// Test generated circuit with expected circuit
    #[test]
    fn parser_circuit_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(1));
        parser.add_witness("y", Fr::from(2));
        parser.add_witness("z", Fr::from(3));
        let generated_circuit = parser.parse("x*y+3*x*x+x*y*z=11");

        let hand_written_circuit = Circuit::default()
            .add_multiplication_gate(
                // gate 0
                (1, 1, Fr::from(1)),
                (1, 0, Fr::from(2)),
                (0, 3, Fr::from(2)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                // gate 1
                (0, 1, Fr::from(3)),
                (1, 2, Fr::from(1)),
                (0, 2, Fr::from(3)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                // gate 2
                (2, 1, Fr::from(3)),
                (0, 0, Fr::from(1)),
                (1, 3, Fr::from(3)),
                Fr::from(0),
            )
            .add_addition_gate(
                // gate 3
                (0, 4, Fr::from(2)),
                (2, 2, Fr::from(3)),
                (0, 5, Fr::from(5)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                // gate 4
                (2, 0, Fr::from(2)),
                (1, 4, Fr::from(3)),
                (1, 5, Fr::from(6)),
                Fr::from(0),
            )
            .add_addition_gate(
                //gate 5
                (2, 3, Fr::from(5)),
                (2, 4, Fr::from(6)),
                (0, 6, Fr::from(11)),
                Fr::from(0),
            )
            .add_addition_gate(
                //gate 6
                (2, 5, Fr::from(11)),
                (1, 6, Fr::from(-11)),
                (2, 6, Fr::from(0)),
                Fr::from(0),
            );

        //Verify if generated circuit is equal to handwritten circuit
        assert_eq!(hand_written_circuit, generated_circuit);
        let compiled_circuit = hand_written_circuit.compile().unwrap();
        //Verify if the handwritten circuit is true
        let proof = prover::generate_proof::<Sha256>(&compiled_circuit);
        assert!(verifier::verify::<Sha256>(&compiled_circuit, proof).is_ok());
    }

    ///Test with a missing witness
    ///
    /// Must panic
    #[should_panic]
    #[test]
    fn parser_missing_witness_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(1));
        parser.add_witness("y", Fr::from(2));
        parser.add_witness("z", Fr::from(3));

        parser.parse("x*y+3*x*x+x*y*z*a=0");
    }

    /// Test with negative variable
    #[test]
    fn parser_negative_witness_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(-1));
        parser.add_witness("y", Fr::from(-2));
        parser.add_witness("z", Fr::from(-3));

        let compiled_circuit = parser.parse("x*y+3*x*x+x*y*z=-1").compile().unwrap();
        let proof = prover::generate_proof::<Sha256>(&compiled_circuit);
        assert!(verifier::verify::<Sha256>(&compiled_circuit, proof).is_ok());
    }

    /// Test parse_string() function
    #[test]
    fn parse_string_test() {
        let result = Parser::parse_string("x * y + 3 * x ^ 2 + x * y * z = 11");
        assert_eq!(result, "x*y+3*x*x+x*y*z=11".to_string());
    }

    /// Test parse_string() function with invalid polynomial string
    ///
    /// Must panic
    #[test]
    #[should_panic]
    fn parse_string_panic_test() {
        let _result = Parser::parse_string("x * y + 3 * x ^ x + x * y * z=0");
    }
}

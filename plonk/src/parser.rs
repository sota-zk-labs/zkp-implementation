use std::collections::{HashMap, HashSet};
use std::ops::Neg;
use ark_bls12_381::Fr;

use crate::circuit::Circuit;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct Gate {
    //Left branch of the circuit
    pub left: Wire,
    //Right branch of the circuit
    pub right: Wire,
    //Bottom part (result) of the circuit
    pub bottom: Wire,
    // type 0: add, type 1: mul, type 2: const
    pub type_of_circuit: i32,
}

impl Gate {
    fn new(left: Wire, right: Wire, bottom: Wire, type_of_circuit: i32) -> Self {
        Gate {
            left,
            right,
            bottom,
            type_of_circuit,
        }
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

#[derive(Default)]
pub struct Parser {
    pub witnesses: HashMap<String, Fr>,
}

impl Parser {
    pub fn add_witness(&mut self, variable: &str, value: Fr) {
        self.witnesses.insert(variable.to_string(), value);
    }

    pub fn parse(self, mut input: String) -> Circuit {
        // x^2 + y^2 = z^2 as a string
        // we check string.trim()[end-2..end] = "0" or not
        // we split by the "=" and then do array[0] + "-" + array[1] + " = 0"
        // x^2 + y^2 - z^2 = 0
        //use a parse system to convert it into
        // x*x + y*y - z*z = 0
        //first count unique variable, in this case 3: "x", "y", "z"
        //ask the value of the variable
        //secondly use recursion to build circuit
        //save value in a vec<vec<>>
        //It could be "x*x+y*y-z*z = 0
        //let polynomial = "x*x+y*y".to_lowercase().to_string();

        //in step 2 we need to separate addition firsts then add multiplication result in
        input = Self::parse_string(input);
        // type 0: add, type 1: mul, type 2: const
        let (gate_list, mut position_map) = self.gen_circuit(input);

        let mut result = Circuit::default();
        println!("{:?}", position_map);
        for gate in gate_list.iter().cloned() {
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
                0 => {
                    result = result.add_addition_gate(left, right, bottom, Fr::from(0));
                }
                1 => {
                    result = result.add_multiplication_gate(left, right, bottom, Fr::from(0));
                }
                2 => {
                    result = result.add_constant_gate(left, right, bottom, Fr::from(0));
                }
                _ => {}
            }
            println!("{:?} {:?} {:?}", left, right, bottom);
        }
        result
    }


    fn gen_circuit(
        &self,
        circuit: String,
    ) -> (Vec<Gate>, HashMap<String, Vec<(usize, usize)>>) {
        let mut gate_list: Vec<Gate> = Vec::new();
        let mut gate_set: HashSet<Gate> = HashSet::new();
        //Map of integer key will be here, it will then be inserted into gen circuit method
        let mut position_map: HashMap<String, Vec<(usize, usize)>> = HashMap::new();

        let split_list: Vec<String> = circuit.split("+").map(|s| s.to_string()).collect();
        //TODO:logic cleaning of the left_mul thingy or at least rename it
        let mut left = {
            let split_list_mul: Vec<String> = split_list[0].split("*").map(|s| s.to_string()).collect();
            let mut left_mul = Wire::new(
                split_list_mul[0].clone(),
                self.get_witness_value(split_list_mul[0].clone().trim().to_string()),
            );
            for j in 1..split_list_mul.len() {
                left_mul = self.gen_mul_circuit(
                    &mut gate_list,
                    &mut gate_set,
                    &mut position_map,
                    left_mul,
                    split_list_mul
                        .get(j)
                        .cloned()
                        .expect("The for loop protect this from panic"),
                );
            }
            left_mul
        };
        for i in 1..split_list.len() {
            let split_list_mul: Vec<String> = split_list[i].split("*").map(|s| s.to_string()).collect();
            let mut left_mul = Wire::new(
                split_list_mul[0].clone(),
                self.get_witness_value(split_list_mul[0].clone().trim().to_string()),
            );
            for j in 1..split_list_mul.len() {
                left_mul = self.gen_mul_circuit(
                    &mut gate_list,
                    &mut gate_set,
                    &mut position_map,
                    left_mul,
                    split_list_mul
                        .get(j)
                        .expect("The for loop protect this from panic")
                        .clone(),
                );
            }
            //Left of the multiplication circuit now turn into the right of a addition circuit
            left = self.gen_add_circuit(
                &mut gate_list,
                &mut gate_set,
                &mut position_map,
                left,
                left_mul,
            );
        }

        (gate_list, position_map)
        //we will save a map of variable key to a stack of position, so all position is reversed
        //first iteration we will have a vector of tuple of 3 value, (left, right, value, type (add, mul or const) )
        //second iteration we will input corresponding position into that value and insert it to the gate system
    }


//The copy constraint define copy values to each other, so in the end of the mul, we swap its value in the add circuit
//we save the position of the result of gates and value of the variable


    fn gen_add_circuit(
        &self,
        gate_list: &mut Vec<Gate>,
        gate_set: &mut HashSet<Gate>,
        position_map: &mut HashMap<String, Vec<(usize, usize)>>,
        left: Wire,
        right: Wire,
    ) -> Wire {
        let gate_number = gate_list.len();
        let left_string = left.clone().value_string;
        let right_string = right.clone().value_string;
        let result = format!("{}+{}", left_string, right_string);
        let result_fr = left.value_fr + right.value_fr;
        let result = Wire::new(result, result_fr);
        let gate = Gate::new(left.clone(), right.clone(), result.clone(), 0);
        //if this gate already exist, skip this move
        if gate_set.get(&gate).is_some() {
            return result;
        }
        gate_list.push(gate.clone());
        gate_set.insert(gate);

        Self::push_into_position_map_or_insert(
            0,
            gate_number,
            position_map,
            left_string.clone(),
        );
        Self::push_into_position_map_or_insert(
            1,
            gate_number,
            position_map,
            right_string,
        );
        Self::push_into_position_map_or_insert(
            2,
            gate_number,
            position_map,
            result.clone().value_string
        );
        result
    }

    fn gen_mul_circuit(
        &self,
        gate_list: &mut Vec<Gate>,
        gate_set: &mut HashSet<Gate>,
        position_map: &mut HashMap<String, Vec<(usize, usize)>>,
        left: Wire,
        right: String,
    ) -> Wire {
        let gate_number = gate_list.len();
        let left_string = left.clone().value_string;
        let right = Wire::new(
            right.trim().to_string(),
            self.get_witness_value(right),
        );
        let result_string = format!("{}*{}", left_string, right.value_string);
        let result_fr = left.value_fr * right.value_fr;
        let result = Wire::new(result_string, result_fr);
        let gate = Gate::new(left.clone(), right.clone(), result.clone(), 1);
        //if this gate already exist, skip this move
        if gate_set.get(&gate).is_some() {
            return result;
        }
        gate_list.push(gate.clone());
        gate_set.insert(gate);


        Self::push_into_position_map_or_insert(
            0,
            gate_number,
            position_map,
            left_string.clone(),
        );
        Self::push_into_position_map_or_insert(
            1,
            gate_number,
            position_map,
            right.value_string,
        );
        Self::push_into_position_map_or_insert (
            2,
            gate_number,
            position_map,
            result.clone().value_string
        );
        result
    }

    //Get the value in Fr for variable in String
    fn get_witness_value(
        &self,
        mut value: String,
    ) -> Fr {
        let mut is_negative = false;
        if &value[..1] == "-" {
            is_negative = true;
            value = value[1..].to_string();
        }
        let result = match self.witnesses.get(&value) {
            //Not a constant, search in map
            Some(value) => value.clone(),
            //Value is a constant insert a constant gate
            None => {
                let value_fr = Fr::from(value.parse::<i32>().unwrap());
                value_fr
            }
        };
        return if is_negative {
            result.neg()
        } else {
            result
        }
    }

    //Insert a value into position map (position_map) by checking if it exists in that map or not
    //TODO: it could have been try_insert() or something but i think it should be in a wrapper instead
    fn push_into_position_map_or_insert(
        wire_number: usize,
        gate_number: usize,
        position_map: &mut HashMap<String, Vec<(usize, usize)>>,
        value: String,
    ) {
        let var_exist = position_map.get(&value).is_some();
        if var_exist {
            position_map
                .get_mut(&value)
                .expect("var_exist guaranty its existence")
                .push((wire_number, gate_number))
        } else {
            position_map.insert(
                value.clone(),
                vec![(wire_number, gate_number)],
            );
        }
    }

    fn parse_string(string: String) -> String {
        let string = string.to_lowercase();
        let mut result = String::new();
        let mut last_char = String::new();
        let mut flag = false;
        for char in string.chars() {
            if char.to_string() == " " {
                continue
            }
            if char.to_string() == "^" {
                flag = true;
            } else if flag {
                if char.is_numeric() {
                    for _ in 0..char.to_string().parse::<i32>().unwrap()-1 {
                        let string_to_add = "*".to_string() + &last_char;
                        result += string_to_add.as_str();
                    }
                    flag = false;
                } else {
                    println!("this char bruh {} ", char);
                    panic!("can't parse polynomial")
                }
            } else {
                last_char = char.to_string();
                result.push(char);
            }
        }
        result
    }
}

//TODO: refactor each function got it own purpose
//TODO: write test case that match the output of this program
//TODO: implement / and - operator
//this was written with async compatibility in mind, so String was used instead of &str

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use sha2::Sha256;

    use crate::{prover, verifier};
    use crate::circuit::Circuit;
    use crate::parser::Parser;

    #[test]
    fn parser_prover_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(1));
        parser.add_witness("y", Fr::from(2));
        parser.add_witness("z", Fr::from(3));
        let compiled_circuit = parser.parse("x*y+3*x*x+x*y*z".to_string()).compile().unwrap();

        // generate proof
        let proof = prover::generate_proof::<Sha256>(&compiled_circuit);

        // verify proof
        assert!(verifier::verify::<Sha256>(&compiled_circuit, proof).is_ok());
    }

    #[test]
    fn parser_circuit_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(1));
        parser.add_witness("y", Fr::from(2));
        parser.add_witness("z", Fr::from(3));
        let generated_circuit = parser.parse("x*y+3*x*x+x*y*z".to_string());

        let hand_written_circuit = Circuit::default()
            .add_multiplication_gate( // gate 0
                (1, 2, Fr::from(1)),
                (1, 0, Fr::from(2)),
                (0, 4, Fr::from(2)),
                Fr::from(0),
            )
            .add_multiplication_gate( // gate 1
                (0, 1, Fr::from(3)),
                (1, 1, Fr::from(1)),
                (0, 2, Fr::from(3)),
                Fr::from(0),
            )
            .add_multiplication_gate( // gate 2
                (2, 1, Fr::from(3)),
                (0, 0, Fr::from(1)),
                (1, 3, Fr::from(3)),
                Fr::from(0),
            )
            .add_addition_gate( // gate 3
                (0, 3, Fr::from(2)),
                (2, 2, Fr::from(3)),
                (0, 5, Fr::from(5)),
                Fr::from(0),
            )
            .add_multiplication_gate( // gate 4
                (2, 0, Fr::from(2)),
                (1, 4, Fr::from(3)),
                (1, 5, Fr::from(6)),
                Fr::from(0),
            )
            .add_addition_gate( //gate 5
                (2, 3, Fr::from(5)),
                (2, 4, Fr::from(6)),
                (2, 5, Fr::from(11)),
                Fr::from(0),
            );

        assert_eq!(hand_written_circuit, generated_circuit);
        let compiled_circuit = hand_written_circuit.compile().unwrap();
        //Verify if the handwritten circuit is true
        let proof = prover::generate_proof::<Sha256>(&compiled_circuit);
        assert!(verifier::verify::<Sha256>(&compiled_circuit, proof).is_ok());
        //Verify if generated circuit is equal to handwritten circuit
    }

    #[should_panic]
    #[test]
    fn parser_missing_witness_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(1));
        parser.add_witness("y", Fr::from(2));
        parser.add_witness("z", Fr::from(3));

        parser.parse("x*y+3*x*x+x*y*z*a".to_string());
    }

    #[test]
    fn parser_negative_witness_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(-1));
        parser.add_witness("y", Fr::from(-2));
        parser.add_witness("z", Fr::from(-3));

        let compiled_circuit = parser.parse("x*y+3*x*x+x*y*z".to_string()).compile().unwrap();
        let proof = prover::generate_proof::<Sha256>(&compiled_circuit);
        assert!(verifier::verify::<Sha256>(&compiled_circuit, proof).is_ok());
    }

    #[test]
    fn parse_string_test() {
        let result = Parser::parse_string("x * y + 3 * x ^ 2 + x * y * z".to_string());
        assert_eq!(result, "x*y+3*x*x+x*y*z".to_string());
    }

    #[test]
    #[should_panic]
    fn parse_string_panic_test() {
        let result = Parser::parse_string("x * y + 3 * x ^ x + x * y * z".to_string());
    }
}

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use ark_bls12_381::Fr;

use crate::circuit::Circuit;
use crate::compiled_circuit::CompiledCircuit;

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

    pub fn parse(self, input: String) -> CompiledCircuit {
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

        // type 0: add, type 1: mul, type 2: const
        let (gate_list, mut position_map) = self.gen_circuit(input);

        //TODO: the swapping for copy constraint is currently stack, try to implement it using
        // list.rotate_right(1) instead

        let mut result = Circuit::default();
        for circuit in gate_list.iter().cloned() {
            println!("{:?}", circuit);
            let left = position_map
                .get_mut(&circuit.left.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let left = (left.0, left.1, Fr::from(circuit.left.value_fr));
            let right = position_map
                .get_mut(&circuit.right.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let right = (right.0, right.1, Fr::from(circuit.left.value_fr));
            let bottom = position_map
                .get_mut(&circuit.bottom.value_string)
                .unwrap()
                .pop()
                .unwrap();
            let bottom = (bottom.0, bottom.1, Fr::from(circuit.bottom.value_fr));
            match circuit.type_of_circuit {
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
        let compiled_circuit = result.compile().unwrap();
        compiled_circuit
    }


    fn gen_circuit(
        &self,
        circuit: String,
    ) -> (Vec<Gate>, HashMap<String, Vec<(usize, usize)>>) {
        let gate_list: Vec<Gate> = Vec::new();
        //Map of integer key will be here, it will then be inserted into gen circuit method
        let position_map: HashMap<String, Vec<(usize, usize)>> = HashMap::new();

        let split_list: Vec<String> = circuit.split("+").map(|s| s.to_string()).collect();
        //TODO:logic cleaning of the left_mul thingy or at least rename it
        let mut left = {
            let split_list_mul: Vec<String> = split_list[0].split("*").map(|s| s.to_string()).collect();
            let mut left_mul = Wire::new(
                split_list_mul[0].clone(),
                get_witness_value(
                    &self.witnesses,
                    gate_list.clone(),
                    position_map,
                    split_list_mul[0].clone().trim().to_string(),
                ),
            );
            for j in 1..split_list_mul.len() {
                left_mul = gen_circuit_mul(
                    &self.witnesses,
                    gate_list.clone(),
                    position_map,
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
                get_witness_value(
                    &self.witnesses,
                    gate_list.clone(),
                    position_map,
                    split_list_mul[0].clone().trim().to_string(),
                ),
            );
            for j in 1..split_list_mul.len() {
                left_mul = gen_circuit_mul(
                    &self.witnesses,
                    gate_list.clone(),
                    position_map,
                    left_mul,
                    split_list_mul
                        .get(j)
                        .expect("The for loop protect this from panic")
                        .clone(),
                );
            }
            //Left of the multiplication circuit now turn into the right of a addition circuit
            left = gen_circuit_add(
                &self.witnesses,
                &mut gate_list,
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
}

//The copy constraint define copy values to each other, so in the end of the mul, we swap its value in the add circuit
//we save the position of the result of gates and value of the variable


fn gen_circuit_add(
    &self,
    gate_list: &mut Vec<Gate>,
    position_map: &mut HashMap<String, Vec<(usize, usize)>>,
    left: Wire,
    right: Wire,
) -> Wire {
    let gate_number = gate_list.len() - 1;
    let left_string = left.clone().value_string;
    let right_string = right.clone().value_string;
    let result = format!("{}+{}", left_string, right_string);
    let result_fr = left.value_fr + right.value_fr;
    let result = Wire::new(result, result_fr);
    gate_list
        .push(Gate::new(left, right, result.clone(), 0));
    //TODO replace left.len() == 1 and right.len() == 1 with left.is_char() and right.is_char()
    push_into_position_map_or_insert(
        0,
        gate_number,
        position_map,
        left_string.clone(),
    );
    push_into_position_map_or_insert(
        1,
        gate_number,
        position_map,
        left_string.clone(),
    );
    push_into_position_map_or_insert(
        2,
        gate_number,
        position_map,
        result.clone().value_string
    );
    result
}

fn gen_circuit_mul(
    map: &HashMap<String, Fr>,
    gate_list: &mut Vec<Gate>,
    position_map: &mut HashMap<String, Vec<(usize, usize)>>,
    left: Wire,
    right: String,
) -> Wire {
    let gate_number = gate_list.len() - 1;
    //TODO: do variable cleanup
    let left_string = left.clone().value_string;
    let right = Wire::new(
        right.trim().to_string(),
        get_witness_value(
            &position_map,
            right
        ),
    );
    let result = format!("{}*{}", left_string, right.value_string);
    let result_fr = left.value_fr * right.value_fr;
    let result = Wire::new(result, result_fr);
    gate_list
        .push(Gate::new(left, right.clone(), result.clone(), 1));


    push_into_position_map_or_insert(
        0,
        gate_number,
        position_map,
        left_string.clone(),
    );
    push_into_position_map_or_insert(
        1,
        gate_number,
        position_map,
        left_string.clone(),
    );
    push_into_position_map_or_insert(
        2,
        gate_number,
        position_map,
        result.clone().value_string
    );
    result
}

//Get the value in Fr for variable in String
fn get_witness_value(
    &self
    position_map: &HashMap<String, Vec<(usize, usize)>>,
    value: String,
) -> Fr {
    match self.witness.get(&value) {
        //Not a constant, search in map
        Some(value) => value.clone(),
        //Value is a constant insert a constant gate
        None => {
            let value_fr = Fr::from(value.parse::<i32>().unwrap());
            /* TODO: evaluate if constant gate was needed and move this block away
            let left = Wire::new(value.clone(), value_fr);
            let right = Wire::new("0".to_string(), Fr::from(0));
            let result = Wire::new(value.clone(), value_fr);
            gate_list
                .push(Gate::new(left.clone(), right.clone(), result.clone(), 2));
            push_into_position_map_or_insert(
                gate_list.clone(),
                position_map,
                left.value_string,
                0,
            );
            push_into_position_map_or_insert(
                gate_list.clone(),
                position_map,
                right.value_string,
                1,
            );
            push_into_position_map_or_insert(
                gate_list.clone(),
                position_map,
                result.value_string,
                2,
            );*/
            value_fr
        }
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
            .push((wire_number, gate_number - 1))
    } else {
        position_map.insert(
            value.clone(),
            vec![(wire_number, gate_number - 1)],
        );
    }
}

//TODO: refactor each function got it own purpose
//TODO: write function that read know that variable is going to change or not -> no clone or rc
//TODO: write test case that match the output of this program
//TODO: this was written with async compatibility in mind, so String was used instead of &str

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use sha2::Sha256;

    use crate::{prover, verifier};
    use crate::circuit::Circuit;
    use crate::parser::Parser;

    #[test]
    fn parser_test_prove() {
        let parser = Parser::default();
        let compiled_circuit = parser.parse("x*y+3*x*x+x*y*z".to_string());

        // generate proof
        let proof = prover::generate_proof::<Sha256>(&compiled_circuit);

        // verify proof
        assert!(verifier::verify::<Sha256>(&compiled_circuit, proof).is_ok());
    }

    #[test]
    fn parser_test() {
        let parser = Parser::default();
        let compiled_circuit = parser.parse("x*y+3*x*x+x*y*z".to_string());

        let compile_circuit = Circuit::default()
            .add_multiplication_gate(
                (0, 1, Fr::from(1)),
                (1, 0, Fr::from(2)),
                (0, 3, Fr::from(2)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (1, 1, Fr::from(1)),
                (0, 0, Fr::from(1)),
                (0, 2, Fr::from(1)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (2, 1, Fr::from(1)),
                (2, 6, Fr::from(3)),
                (1, 3, Fr::from(3)),
                Fr::from(0),
            )
            .add_addition_gate(
                (0, 4, Fr::from(2)),
                (2, 2, Fr::from(3)),
                (0, 5, Fr::from(5)),
                Fr::from(0),
            )
            .add_multiplication_gate(
                (2, 0, Fr::from(2)),
                (1, 4, Fr::from(3)),
                (1, 5, Fr::from(6)),
                Fr::from(0),
            )
            .add_addition_gate(
                (2, 3, Fr::from(5)),
                (2, 4, Fr::from(6)),
                (2, 5, Fr::from(11)),
                Fr::from(0),
            )
            .add_constant_gate(
                (0, 6, Fr::from(3)),
                (1, 6, Fr::from(0)),
                (1, 2, Fr::from(3)),
                Fr::from(0),
            )
            .compile()
            .unwrap();

        // verify proof
        assert_eq!(compile_circuit, compiled_circuit)
    }

    #[test]
    fn new_test() {
        let mut parser = Parser::default();
        parser.add_witness("x", Fr::from(1));
        parser.add_witness("y", Fr::from(2));
        parser.add_witness("z", Fr::from(3));

        parser.parse("x*y+3*x*x+x*y*z".to_string());
    }

    #[test]
    fn test1() {
        
    }
}

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
    pub type_of_circuit: i32
}

impl Gate {
    fn new(left: Wire, right: Wire, bottom: Wire, type_of_circuit: i32) -> Self {
        Gate {
            left,
            right,
            bottom,
            type_of_circuit
        }
    }
}

#[derive(Clone, Debug)]
struct Wire {
    value_string: String,
    value_fr: Fr
}

impl Wire {
    fn new(value_string: String, value_fr: Fr) -> Self {
        Wire {
            value_string,
            value_fr
        }
    }
}

#[derive(Default)]
pub struct Parser {}


impl Parser {
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
        let map: Rc<RefCell<HashMap<String, Fr>>> = Rc::new(RefCell::new(HashMap::new()));
        //end of step 1 we will have
        //TODO: change std HashMap into hash-brown or st
        //TODO: placeholder for input value
        map.borrow_mut().insert("x".to_string(), Fr::from(1));
        map.borrow_mut().insert("y".to_string(), Fr::from(2));
        map.borrow_mut().insert("z".to_string(), Fr::from(3));

        //Map of integer key will be here, it will then be inserted into gen circuit method
        let variable_map: Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>> = Rc::new(RefCell::new(HashMap::new()));
        // type 0: add, type 1: mul, type 2: const
        let gate_list: Rc<RefCell<Vec<Gate>>> = Rc::new(RefCell::new(Vec::new()));
        gen_circuit(map.clone(), gate_list.clone(), variable_map.clone(), input);


        // Variable map is a stack of position, we pop the position and assign it to the corresponding variable

        let mut result = Circuit::default();
        for circuit in gate_list.borrow_mut().iter().cloned() {
            println!("{:?}", circuit);
            let left = variable_map.borrow_mut().get_mut(&circuit.left.value_string).unwrap().pop().unwrap();
            //replace placeholder by a number contain that value
            // left.0 and left.1 is position of the variable and the last variable is the value for that pos
            let left = (left.0, left.1, Fr::from(circuit.left.value_fr));
            let right = variable_map.borrow_mut().get_mut(&circuit.right.value_string).unwrap().pop().unwrap();
            let right = (right.0, right.1, Fr::from(circuit.left.value_fr));
            let bottom = variable_map.borrow_mut().get_mut(&circuit.bottom.value_string).unwrap().pop().unwrap();
            let bottom = (bottom.0, bottom.1, Fr::from(circuit.bottom.value_fr));
            match circuit.type_of_circuit {
                0 => {
                    result = result.add_addition_gate(left, right, bottom, Fr::from(0));
                },
                1 => {
                    result = result.add_multiplication_gate(left, right, bottom, Fr::from(0));
                },
                2 => {
                    result = result.add_constant_gate(left, right, bottom, Fr::from(0));
                },
                _ => {}
            }
            println!("{:?} {:?} {:?}", left, right, bottom);
        }
        let compiled_circuit = result.compile().unwrap();
        compiled_circuit
    }
}

//The copy constraint define copy values to each other, so in the end of the mul, we swap its value in the add circuit
//we save the position of the result of gates and value of the variable

fn gen_circuit(map: Rc<RefCell<HashMap<String, Fr>>>, gate_list: Rc<RefCell<Vec<Gate>>>, variable_map : Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>>, circuit: String) -> bool {
    let split_list:Vec<String> = circuit.split("+").map(|s| s.to_string()).collect();

    let mut left = {
        let split_list_mul:Vec<String> = split_list[0].split("*").map(|s| s.to_string()).collect();
        let mut left_mul = Wire::new(split_list_mul[0].clone(), get_value_fr(map.clone(), split_list_mul[0].clone().trim().to_string()));
        for j in 1..split_list_mul.len() {
            left_mul = gen_circuit_mul(map.clone(), gate_list.clone(), variable_map.clone(), left_mul, split_list_mul.get(j).cloned().expect("The for loop protect this from panic"));
        }
        left_mul
    };
    for i in 1..split_list.len() {
        let split_list_mul:Vec<String> = split_list[i].split("*").map(|s| s.to_string()).collect();
        let mut left_mul = Wire::new(split_list_mul[0].clone(), get_value_fr(map.clone(), split_list_mul[0].clone().trim().to_string()));
        for j in 1..split_list_mul.len() {
            left_mul = gen_circuit_mul(map.clone(), gate_list.clone(), variable_map.clone(), left_mul, split_list_mul.get(j).expect("The for loop protect this from panic").clone());
        }
        //Left of the multiplication circuit now turn into the right of a addition circuit
        left = gen_circuit_add(map.clone(), gate_list.clone(), variable_map.clone(), left, left_mul);
    }

    true
    //we will save a map of variable key to a stack of position, so all position is reversed
    //first iteration we will have a vector of tuple of 3 value, (left, right, value, type (add, mul or const) )
    //second iteration we will input corresponding position into that value and insert it to the gate system
}

fn gen_circuit_add(map: Rc<RefCell<HashMap<String, Fr>>>, gate_list: Rc<RefCell<Vec<Gate>>>,
                   variable_map: Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>>, left: Wire, right: Wire) -> Wire {
    let left_string = left.clone().value_string;
    let right_string = right.clone().value_string;
    let result = format!("{}+{}", left_string, right_string);
    let result_fr = left.value_fr + right.value_fr;
    let result = Wire::new(result, result_fr);
    gate_list.borrow_mut().push(Gate::new(left, right, result.clone(), 0));
    //TODO replace left.len() == 1 and right.len() == 1 with left.is_char() and right.is_char()
    insert(gate_list.clone(), variable_map.clone(), left_string, 0);
    insert(gate_list.clone(), variable_map.clone(), right_string, 1);
    insert(gate_list.clone(), variable_map.clone(), result.clone().value_string, 2);
    result
}

fn gen_circuit_mul(map: Rc<RefCell<HashMap<String, Fr>>>, gate_list: Rc<RefCell<Vec<Gate>>>,
                   variable_map: Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>>, left: Wire, right: String) -> Wire {
    let left_string = left.clone().value_string;
    let right = Wire::new(right.trim().to_string(), get_value_fr(map, right.to_string()));
    let result = format!("{}*{}", left_string, right.value_string);
    let result_fr = left.value_fr * right.value_fr;
    let result= Wire::new(result, result_fr);
    gate_list.borrow_mut().push(Gate::new(left, right.clone(), result.clone(), 1));
    insert(gate_list.clone(), variable_map.clone(), left_string.clone(), 0);
    insert(gate_list.clone(), variable_map.clone(), right.value_string, 1);
    insert(gate_list.clone(), variable_map.clone(), result.clone().value_string, 2);
    result
}

fn get_value_fr(map: Rc<RefCell<HashMap<String, Fr>>>, value: String) -> Fr {
    match map.borrow().get(&value) {
        Some(value) => {value.clone()},
        None => {Fr::from(value.parse::<i32>().unwrap())}
    }
}

fn insert(gate_list: Rc<RefCell<Vec<Gate>>>, variable_map: Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>>, value: String, position_in_circuit: usize) {
    let var_exist = variable_map.borrow_mut().get(&value).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(&value).expect("var_exist guaranty its exist").push((position_in_circuit, gate_list.borrow_mut().len()-1))
    } else {
        variable_map.borrow_mut().insert(value.clone(), vec!((position_in_circuit, gate_list.borrow_mut().len()-1)));
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use sha2::Sha256;

    use crate::circuit::Circuit;
    use crate::parser::Parser;
    use crate::{prover, verifier};

    #[test]
    fn parser_test() {
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
}
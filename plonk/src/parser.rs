use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use ark_bls12_381::Fr;
use crate::circuit::Circuit;
use crate::compiled_circuit::CompiledCircuit;
use crate::gate::Position;
use crate::gate::Position::Pos;

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
        let polynomial = "x*x+y*y".to_lowercase().to_string();

        //in step 2 we need to separate addition firsts then add multiplication result in
        let mut map: Rc<RefCell<HashMap<String, Fr>>> = Rc::new(RefCell::new(HashMap::new()));
        //end of step 1 we will have
        //change std HashMap into hash-brown or st
        map.insert("x".to_string(), Fr::from(3));
        map.insert("y".to_string(), Fr::from(4));
        map.insert("z".to_string(), Fr::from(5));

        //Map of integer key will be here, it will then be inserted into gen circuit method
        let variable_map: Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>> = Rc::new(RefCell::new(HashMap::new()));
        // type 0: add, type 1: mul, type 2: const
        let circuit_list: Rc<RefCell<Vec<(String, String, String, i32, i32)>>> = Rc::new(RefCell::new(Vec::new()));
        gen_circuit(circuit_list.clone(), variable_map.clone(), polynomial);

        println!("{:?}", variable_map);

        let mut result = Circuit::default();
        for i in circuit_list.borrow_mut().iter().cloned() {
            println!("{:?}", i);
            let left = variable_map.borrow_mut().get_mut(&i.0).unwrap().pop().unwrap();
            //replace placeholder by a number contain that value
            let left = (left.0, left.1, Fr::from(0));
            let right = variable_map.borrow_mut().get_mut(&i.1).unwrap().pop().unwrap();
            let right = (right.0, right.1, Fr::from(0));
            let bottom = variable_map.borrow_mut().get_mut(&i.2).unwrap().pop().unwrap();
            let bottom = (bottom.0, bottom.1, Fr::from(0));
            match i.3 {
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
        }
        let compiled_circuit =
        result.compile().unwrap();
        println!("{:?}", compiled_circuit);
        compiled_circuit
    }
}

//The copy constraint define copy values to each other, so in the end of the mul, we swap its value in the add circuit
//we save the position of the result of gates and value of the variable

fn gen_circuit(map: Rc<RefCell<HashMap<String, Fr>>>, circuit_list: Rc<RefCell<Vec<(String, String, String, i32, i32)>>>, variable_map : Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>>, circuit: String) -> bool {
    let split_list:Vec<String> = circuit.split("+").map(|s| s.to_string()).collect();

    let mut left = {
        let split_list_mul:Vec<String> = split_list[0].split("*").map(|s| s.to_string()).collect();
        let mut left_mul = split_list_mul[0].clone();
        for j in 1..split_list_mul.len() {
            left_mul = gen_circuit_mul(map.clone(), circuit_list.clone(), variable_map.clone(), left_mul, split_list_mul.get(j).cloned().expect("The for loop protect this from panic"));
        }
        left_mul
    };
    for i in 1..split_list.len() {
        let split_list_mul:Vec<String> = split_list[i].split("*").map(|s| s.to_string()).collect();
        let mut left_mul = split_list_mul[0].clone();
        for j in 1..split_list_mul.len() {
            left_mul = gen_circuit_mul(map.clone(), circuit_list.clone(), variable_map.clone(), left_mul, split_list_mul.get(j).expect("The for loop protect this from panic").clone());
        }
        //Left of the multiplication circuit now turn into the right of a addition circuit
        left = gen_circuit_add(map.clone(), circuit_list.clone(), variable_map.clone(), left, left_mul);
    }

    true
    //we will save a map of variable key to a stack of position, so all position is reversed
    //first iteration we will have a vector of tuple of 3 value, (left, right, value, type (add, mul or const) )
    //second iteration we will input corresponding position into that value and insert it to the gate system
}

fn gen_circuit_add(map: Rc<RefCell<HashMap<String, Fr>>>, circuit_list: Rc<RefCell<Vec<(String, String, String, i32, i32)>>>, variable_map: Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>>, left: String, right: String) -> String {
    let left = left.trim();
    let right = right.trim();
    let result = format!("{}+{}", left, right);
    circuit_list.borrow_mut().push((left.to_string(), right.to_string(), result.clone(),  0));
    println!("{} {}", left, variable_map.borrow_mut().get(left).is_some());
    //TODO replace left.len() == 1 and right.len() == 2 with left.is_char() and right.is_char()
    let var_exist = variable_map.borrow_mut().get(left).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(left).expect("var_exist guaranty its exist").push((0, circuit_list.borrow_mut().len()-1));
    } else if left.len() == 1 {
        variable_map.borrow_mut().insert(left.to_string(), vec!((0, circuit_list.borrow_mut().len()-1)));
    }
    let var_exist = variable_map.borrow_mut().get(right).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(right).expect("var_exist guaranty its exist").push((1, circuit_list.borrow_mut().len()-1))
    } else if right.len() == 1 {
        variable_map.borrow_mut().insert(right.to_string(), vec!((1, circuit_list.borrow_mut().len()-1)));
    }
    let var_exist = variable_map.borrow_mut().get(&result).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(&result).expect("var_exist guaranty its exist").push((3, circuit_list.borrow_mut().len()-1))
    } else {
        variable_map.borrow_mut().insert(result.clone(), vec!((3, circuit_list.borrow_mut().len()-1)));
    }
    result.clone()
}

fn gen_circuit_mul(map: Rc<RefCell<HashMap<String, Fr>>>, mut circuit_list: Rc<RefCell<Vec<(String, String, String, i32, i32)>>>, mut variable_map: Rc<RefCell<HashMap<String, Vec<(usize, usize)>>>>, left: String, right: String) -> String {
    let left = left.trim();
    let right = right.trim();
    let result = format!("{}*{}", left, right);
    circuit_list.borrow_mut().push((left.to_string(), right.to_string(), result.clone(), 1));
    let var_exist = variable_map.borrow_mut().get(left).is_some();
    println!("{} {}", left, variable_map.borrow_mut().get(left).is_some());
    if var_exist {
        variable_map.borrow_mut().get_mut(left).expect("var_exist guaranty its exist").push((0, circuit_list.borrow_mut().len()-1));
    } else if left.len() == 1 {
        variable_map.borrow_mut().insert(left.to_string(), vec!((0, circuit_list.borrow_mut().len()-1)));
    }
    let var_exist = variable_map.borrow_mut().get(right).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(right).expect("var_exist guaranty its exist").push((1, circuit_list.borrow_mut().len()-1))
    } else if right.len() == 1 {
        variable_map.borrow_mut().insert(right.to_string(), vec!((1, circuit_list.borrow_mut().len()-1)));
    }
    let var_exist = variable_map.borrow_mut().get(&result).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(&result).expect("var_exist guaranty its exist").push((3, circuit_list.borrow_mut().len()-1))
    } else {
        variable_map.borrow_mut().insert(result.clone(), vec!((3, circuit_list.borrow_mut().len()-1)));
    }
    result.clone()
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;

    use crate::circuit::Circuit;
    use crate::parser::Parser;

    #[test]
    fn parser_test() {
        let parser = Parser::default();
        let complied_circuit = parser.parse("x*y + 3*x*x + x*y*z".to_string());
        let expected_compiled_circuit = Circuit::default()
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


        assert_eq!(complied_circuit, expected_compiled_circuit)
    }
}
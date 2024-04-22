use std::cell::RefCell;
use ark_bls12_381::Fr;
use std::collections::HashMap;
use std::env::var;
use std::rc::Rc;
use plonk::gate::Position;
use plonk::gate::Position::Pos;

fn main() {
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
    let polynomial = "x*x+y*y=z*z".to_lowercase().to_string();

    //in step 2 we need to separate addition firsts then add multiplication result in
    let mut map:HashMap<String, Fr> = HashMap::new();
    //end of step 1 we will have
    //change std HashMap into hash-brown or st
    map.insert("x".to_string(), Fr::from(3));
    map.insert("y".to_string(), Fr::from(4));
    map.insert("z".to_string(), Fr::from(5));

    //Map of integer key will be here, it will then be inserted into gen circuit method
    let variable_map: Rc<RefCell<HashMap<String, Vec<Position>>>> = Rc::new(RefCell::new(HashMap::new()));
    // type 0: add, type 1: mul, type 2: const
    let circuit_list : Rc<RefCell<Vec<(String, String, String, i32)>>> = Rc::new(RefCell::new(Vec::new()));
    let split_list:Vec<String> = polynomial.split("=").map(|s| s.to_string()).collect();
    gen_circuit(circuit_list.clone(), variable_map.clone(), split_list.get(0).expect("it will have an equal sign in the middle, at least that's what i think").clone());
    gen_circuit(circuit_list.clone(), variable_map.clone(), split_list.get(1).expect("it will have an equal sign in the middle, at least that's what i think").clone());
}

//The copy constraint define copy values to each other, so in the end of the mul, we swap its value in the add circuit
//we save the position of the result of gates and value of the variable

fn gen_circuit(circuit_list: Rc<RefCell<Vec<(String, String, String, i32)>>>, variable_map : Rc<RefCell<HashMap<String, Vec<Position>>>>, circuit: String) -> bool {
    let split_list:Vec<String> = circuit.split("+").map(|s| s.to_string()).collect();

    let mut left = {
        let split_list_mul:Vec<String> = split_list[0].split("*").map(|s| s.to_string()).collect();
        let mut left_mul = split_list_mul[0].clone();
        for j in 1..split_list_mul.len() {
            left_mul = gen_circuit_mul(circuit_list.clone(), variable_map.clone(), left_mul, split_list_mul.get(j).cloned().expect("The for loop protect this from panic"));
        }
        left_mul
    };
    for i in 1..split_list.len() {
        let split_list_mul:Vec<String> = split_list[i].split("*").map(|s| s.to_string()).collect();
        let mut left_mul = split_list_mul[0].clone();
        for j in 1..split_list_mul.len() {
            left_mul = gen_circuit_mul(circuit_list.clone(), variable_map.clone(), left_mul, split_list_mul.get(j).expect("The for loop protect this from panic").clone());
        }
        //Left of the multiplication circuit now turn into the right of a addition circuit
        left = gen_circuit_add(circuit_list.clone(), variable_map.clone(), left, left_mul);
    }

    let binding = variable_map.borrow_mut();
    let temp = binding.iter().clone().collect::<Vec<(&String, &Vec<Position>)>>();
    for i in temp {
        println!("{}", i.0);
        for j in i.1 {
            println!("    {:?}", j);
        }
    }
    println!("{:?}", circuit_list);
    true
    //we will save a map of variable key to a stack of position, so all position is reversed
    //first iteration we will have a vector of tuple of 3 value, (left, right, value, type (add, mul or const) )
    //second iteration we will input corresponding position into that value and insert it to the gate system
}

fn gen_circuit_add(circuit_list: Rc<RefCell<Vec<(String, String, String, i32)>>>, variable_map: Rc<RefCell<HashMap<String, Vec<Position>>>>, left: String, right: String) -> String {
    let left = left.trim();
    let right = right.trim();
    let result = format!("{}+{}", left, right);
    circuit_list.borrow_mut().push((left.to_string(), right.to_string(), result.clone(), 0));
    //TODO replace left.len() == 1 and right.len() == 2 with left.is_char() and right.is_char()
    if left.len() == 1 {
        let var_exist = variable_map.borrow_mut().get(left).is_some();
        if var_exist {
            variable_map.borrow_mut().get_mut(left).expect("var_exist guaranty its exist").push(Pos(0, circuit_list.borrow_mut().len()-1))
        } else {
            variable_map.borrow_mut().insert(left.to_string(), vec!(Pos(0, circuit_list.borrow_mut().len()-1)));
        }
    }
    if right.len() == 1 {
        let var_exist = variable_map.borrow_mut().get(right).is_some();
        if var_exist {
            variable_map.borrow_mut().get_mut(right).expect("var_exist guaranty its exist").push(Pos(0, circuit_list.borrow_mut().len()-1))
        } else {
            variable_map.borrow_mut().insert(right.to_string(), vec!(Pos(0, circuit_list.borrow_mut().len()-1)));
        }
    }
    let var_exist = variable_map.borrow_mut().get(&result).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(&result).expect("var_exist guaranty its exist").push(Pos(3, circuit_list.borrow_mut().len()-1))
    } else {
        variable_map.borrow_mut().insert(result.clone(), vec!(Pos(3, circuit_list.borrow_mut().len()-1)));
    }
    result.clone()
}

fn gen_circuit_mul(mut circuit_list: Rc<RefCell<Vec<(String, String, String, i32)>>>, mut variable_map: Rc<RefCell<HashMap<String, Vec<Position>>>>, left: String, right: String) -> String {
    let left = left.trim();
    let right = right.trim();
    let result = format!("{}*{}", left, right);
    circuit_list.borrow_mut().push((left.to_string(), right.to_string(), result.clone(), 1));
    let var_exist = variable_map.borrow_mut().get(left).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(left).expect("var_exist guaranty its existence").push(Pos(0, circuit_list.borrow_mut().len()-1));
    } else if left.len() == 1 {
        variable_map.borrow_mut().insert(left.to_string(), vec!(Pos(0, circuit_list.borrow_mut().len()-1)));
    }
    let var_exist = variable_map.borrow_mut().get(right).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(right).expect("var_exist guaranty its exist").push(Pos(0, circuit_list.borrow_mut().len()-1));
    } else if right.len() == 1 {
        variable_map.borrow_mut().insert(right.to_string(), vec!(Pos(0, circuit_list.borrow_mut().len()-1)));
    }
    let var_exist = variable_map.borrow_mut().get(&result).is_some();
    if var_exist {
        variable_map.borrow_mut().get_mut(&result).expect("var_exist guaranty its exist").push(Pos(3, circuit_list.borrow_mut().len()-1))
    } else {
        variable_map.borrow_mut().insert(result.clone(), vec!(Pos(3, circuit_list.borrow_mut().len()-1)));
    }
    result.clone()
}


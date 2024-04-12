use crate::types::Poly;

pub fn print_poly(poly: &Poly) {
    println!();
    for (i, p) in poly.iter().enumerate() {
        println!("{}.X^{}", p, i);
    }
    println!();
}
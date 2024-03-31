use ark_ff::PrimeField;

// A transcript is a list of Merkle root.
pub struct Transcript<F: PrimeField>{
    data: Vec<F>
}

impl <F:PrimeField> Transcript<F> {
    pub fn new() -> Self {
        Self {
            data: Vec::new()
        }
    }

    pub fn append(&mut self, merkle_root: &F) {
        self.data.push(merkle_root.clone());
    }

    pub fn generate_a_challenge(&self) -> F {
        let challenge = F::ZERO;
        // Todo: implement generate function.
        challenge
    }
    // generate challenges with data.
    pub fn generate_challenge_list(&self, number: usize) -> Vec<F>{
        let challenges = Vec::new();
        // Todo: implement generate function.
        challenges
    }
}
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
        let challenge = F::ONE;
        // Todo: implement generate function.
        challenge
    }
    // generate challenges with data.
    pub fn generate_challenge_list(&self, number: usize) -> Vec<F>{
        let mut challenges = Vec::new();
        for i in 0..number {
            challenges.push(F::ONE);
        }
        // Todo: implement generate function.
        challenges
    }

    pub fn generate_a_index(&self) -> usize {
        // Todo: implement generate function
        1
    }

    pub fn generate_index_list(&self, number: usize) -> Vec<usize> {
        // Todo: implement generate function
        let mut indexes = Vec::new();
        for i in 0..number {
            indexes.push(i + 1);
        }
        indexes
    }
}
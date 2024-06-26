# FRI implementation

## Overview
This is an implementation of FRI. You all can use this one as a library.

## Details
This is an implementation of [FRI protocol](https://eccc.weizmann.ac.il/report/2017/134/).
We implement all the relevant steps for both proof generation and verification.
For detailed code, please refer to the `prover.rs`and `verifier.rs` files located in the `src`
directory.

### What we use ?
We utilize the [Goldilocks field](https://xn--2-umb.com/22/goldilocks/)
and [SHA256](https://en.wikipedia.org/wiki/SHA-2) for the hash function.

All the dependencies utilized in this project are sourced from the `ark` (or `arkworks`) 
crates. For more information, please visit [arkworks.rs](https://arkworks.rs/).


### Set up

Before proceeding, it's advisable to review the documentation on how to utilize this library:

- Clone this repository:
    ```
    git clone https://github.com/sota-zk-lab/zkp-implementation.git
    ```
- Enter to the `fri` folder and run:
    ```
    cargo run --example fri-example   
    ```
The above code will run the `main` function in `example.rs` files located in the `examples`
directory, which is the example usage of this library.

### How it works

We recommend reading our documentation of FRI 
[here](https://github.com/sota-zk-labs/zkp-documents/blob/main/docs/fri.md) and slide 
[here](https://github.com/sota-zk-labs/zkp-documents/blob/main/presentations/fri_implementation.pptx).

To run our library, it's essential understand how to choose **blowup factor** and **number of queries**.
The blowup factor is the inverse of the 
[Reed-Solomon code rate](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction#Constructions_(encoding))
. The code rate $\rho$ is often chosen as $1/2$ (actually, $\rho \le 1/2$). Increasing the blowup factor 
results in a slower prover performance but reduces verifier costs.

To achieve $\lambda$ [bits of security](https://en.wikipedia.org/wiki/Security_level),
certain conditions must be met:
- The hash function used for building Merkle trees needs to have at least $2\lambda$ output bits. 
- The field needs to have at least $2^{\lambda}$ elements
- The number of queries should be $\lceil \lambda / log_2\rho^{-1}$.

In our implementation, we employ the SHA256 hash function, producing 256 bits of output. However, our 
field is Goldilocks, which has a modulus of $p = 2^{64} - 2^{32} + 1$, leading to a security
parameter $\lambda$ of 64.

### Run

This library comes with some unit and integration tests. Run these tests with this command:
```
cargo test
```

You can view each round in generating proof step and verifying step does by:
```
cargo test  -- --nocapture
```

## References
[Fast Reed-Solomon Interactive Oracle Proofs of Proximity](https://eccc.weizmann.ac.il/report/2017/134/)<br/>
Eli Ben-Sasson, Iddo Bentov, Ynon Horesh, Michael Riabzev

[Anatomy of a STARK, Part 3: FRI](https://aszepieniec.github.io/stark-anatomy/fri)<br/>
Aszepieniec

[How to code FRI from scratch](https://blog.lambdaclass.com/how-to-code-fri-from-scratch/) <br/>
Lambda Class

[STARKs, Part II: Thank Goodness It's FRI-day](https://vitalik.eth.limo/general/2017/11/22/starks_part_2.html)<br/>
Vitalik Buterin










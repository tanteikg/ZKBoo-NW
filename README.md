# ZKBoo

Zero Knowledge Prover and Verifier for Boolean Circuits. Currently available is a prover and verifier for SHA-1 and SHA-256. They on OpenSSL for doing commits and randomness generation and use OpenMP for parallelization.

When starting either prover, it will prompt for an input to hash. After entering the input, the proof will be generated as a file in the directory the program resides in. The file is named out<NUM_ROUNDS>.bin where <NUM_ROUNDS> is the number of rounds of the algorithm run (Set to 136 by defauly, but can be changed in shared.h. Likewise, the verifier will look for a file in its directory with the same naming syntax to verify.

This was improved on by [ZKB++](https://eprint.iacr.org/2017/279.pdf), an improved version of ZKBOO with NIZK proofs that are less than half the size of ZKBOO proofs. Moreover, benchmarks show that this size reduction comes at no extra computational cost.

# Dec 2022. Author: Tan Teik Guan  

Extended the ZKBoo implementation with more MPC-in-the-head implementations for SHA512 and RIPEMD160.

We hope to use this as a reference for more post-quantum solutions in the future. 



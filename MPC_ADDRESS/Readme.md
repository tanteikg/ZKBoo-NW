## Proof of Address Ownership (PoAO)

To build a decentralized proof of address ownership

# Current situation

* Web3 Service Providers need to provide transparency without sacrificing security
* Proof of Reserves (PoR) is important to prove their ability to match customer deposits. 
* Verification of ownership of wallet addresses is a key step in the PoR verification. 
* Yet this verification is centralized

# Problem

* The known method to prove ownership of an address is to use the private key associated with the address to perform a transaction.
* Issues:
 * What transaction should the service provider perform?
 * Since the transaction details are public, how can the service provider claim ownership of it
    ==> Need a 3rd party auditor to manually certify
 * This exposes the public key of the address
    ==> Address is no longer quantum-secure.

# Challenge

* Can a service provider provide the Proof-of-address ownership in a decentralized way?
* Yes, using Zero-knowledge MPC-in-the-head (MitH) [IKOS]
* Using MitH, we can show the computation of the wallet address using the public key without revealing the public key

# Setup

* Proof Generation (can be done offline)
 * Service Provider enters public key and name of service provider
 * ZKProof is generated, downloaded, to be published by the Service Provider
* Proof Verification
 * Anyone can upload the proof to check the validity of the claim

# Benefits

* Decentralized
 * No 3rd party needed to carry out address check

* Privacy Preserving
 * Public key is not exposed
 * Quantum-secure

* Cross-chain Proof verification
 * No manual intervention needed
 * Can support cross-chain verification

# Future extensions

* Support more wallet types (beyond Dogecoin, Bitcoin)
* Optimization of proof speed and size by using Katz, Kolesnikov and Wang (KKW) [KKW] instead of ZKBoo.
* Implementing the oracle as a cross-chain bridge, and posting the verification results as an IC certified response 
* Inclusion of ECC public key MPC-in-the-head computation to prove true ownership of address
* Support Blockchain post-quantum migration by implementing BIP39/BIP32 MPC-in-the-head computation to prove quantum-secure ownership of address 

Jan 2023


 
 

# Quick Start

Get started with ZKPDF in minutes! This guide will walk you through setting up a zkPDF project using our complete template.

## Starting with zkPDF Template

The fastest way to get started is using our complete zkPDF template:

1. **Clone the zkPDF template**:

   ```bash
   git clone https://github.com/privacy-ethereum/zkpdf-template.git
   cd zkpdf-template
   ```

2. **Install SP1** (if not already installed):

   ```bash
   curl -L https://sp1.succinct.xyz | bash
   source ~/.bashrc
   ```

3. **Build the project**:
   ```bash
   cargo build
   ```

## Understanding the Template Structure

The zkPDF template includes everything you need:

- **`program/src/main.rs`**: SP1 program with zkPDF integration
- **`script/src/bin/main.rs`**: CLI tools for execution and proving
- **`script/src/bin/evm.rs`**: EVM-compatible proof generation
- **`samples/`**: Sample PDFs for testing
- **`contracts/`**: Smart contracts for on-chain verification

## Understanding zkPDF Verification

Before diving into the code, let's understand how zkPDF verification works:

### The verify_and_extract Method

The `verify_and_extract` method is the core function that:

1. **Parses PDF Structure**: Extracts text content and embedded digital signatures
2. **Validates Signatures**: Verifies PKCS#7/CMS digital signatures using cryptographic validation
3. **Extracts Information**: Pulls out specific data like GST numbers, legal names, or any text content
4. **Generates Commitments**: Creates cryptographic hashes for document integrity
5. **Returns Results**: Provides verification status and extracted data without revealing sensitive information

This method abstracts away all the complex PDF parsing, signature validation, and cryptographic operations, making it easy to verify document authenticity while preserving privacy.

## Your First zkPDF Program

The template's `program/src/main.rs` shows GST certificate verification:

```rust
//! GST Certificate Verification Program
//!
//! This program verifies GST certificate PDFs and extracts key information:
//! - GST number
//! - Legal name
//! - Digital signature validity
//! - Document commitment hash
//! - Public key hash
//!
//! The program runs inside the SP1 zkVM to generate zero-knowledge proofs
//! that prove the document is valid without revealing sensitive data.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::keccak256;
use alloy_sol_types::SolType;
use zkpdf_template_lib::{utils::generate_commitment, verify_gst_certificate, PublicValuesStruct};

pub fn main() {
    // Read PDF bytes as input to the program.
    let pdf_bytes = sp1_zkvm::io::read::<Vec<u8>>();

    // Verify the GST certificate and extract information.
    let gst_cert =
        verify_gst_certificate(pdf_bytes.clone()).expect("Failed to verify GST certificate");

    // Generate commitment hash using the new function
    let document_commitment = generate_commitment(&gst_cert);
    let public_key_hash = keccak256(&gst_cert.signature.public_key);

    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        gst_number: gst_cert.gst_number,
        legal_name: gst_cert.legal_name,
        signature_valid: gst_cert.signature.is_valid,
        document_commitment: document_commitment
            .as_slice()
            .try_into()
            .expect("Failed to convert document commitment to FixedBytes"),
        public_key_hash: public_key_hash
            .as_slice()
            .try_into()
            .expect("Failed to convert public key hash to FixedBytes"),
    });

    // Commit to the public values of the program.
    sp1_zkvm::io::commit_slice(&bytes);
}
```

## Running Your Project

The template comes with GST certificate samples ready to use:

1. **Execute the program**:

   ```bash
   cd script
   cargo run --release -- --execute
   ```

2. **Generate a core proof**:

   ```bash
   cargo run --release -- --prove
   ```

3. **Generate an EVM-compatible proof**:

   ```bash
   # Groth16 proof
   cargo run --release --bin evm -- --system groth16

   # PLONK proof
   cargo run --release --bin evm -- --system plonk
   ```

4. **Use your own GST certificate**:

   ```bash
   # Execute with custom GST certificate
   cargo run --release --bin evm -- --system groth16 --pdf-path /path/to/your/gst-certificate.pdf

   # Generate proof with custom certificate
   cargo run --release --bin evm -- --system plonk --pdf-path /path/to/your/gst-certificate.pdf
   ```

## Generating Groth16 Proofs

In the following sections, we'll see how to generate Groth16 proofs, which are optimized for on-chain verification. Groth16 proofs offer:

- **Efficient Verification**: Fast verification on Ethereum and other EVM-compatible chains
- **Small Proof Size**: Compact proofs that reduce gas costs
- **Wide Compatibility**: Supported by most zero-knowledge proof systems

The template includes both Groth16 and PLONK proof generation options, with Groth16 being the recommended choice for blockchain applications.

## Next Steps

- **[API Reference](./api-reference.md)**: Complete reference for zkPDF library functions and usage
- **[Prover Network](./prover-network.md)**: Learn how to use the Succinct Prover Network for distributed proving
- **[Architecture](./architecture.md)**: Learn how ZKPDF works under the hood
- **[Proving](./proving.md)**: Generate zero-knowledge proofs
- **[Verification](./verification.md)**: Verify proofs on-chain

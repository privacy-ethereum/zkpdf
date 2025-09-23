# PDF Verification Circuits

Zero-knowledge circuits for PDF text extraction and digital signature verification using [SP1](https://github.com/succinctlabs/sp1). Generates cryptographic proofs that specific text appears in signed PDF documents.

## 🎯 **Overview**

This project provides SP1 circuits that can:

- Extract text from PDF documents
- Verify digital signatures
- Prove that specific text appears at exact positions
- Generate cryptographic proofs for blockchain verification

## 🚀 **Quick Start**

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
zkpdf-lib = { git = "https://github.com/privacy-ethereum/zkpdf", branch = "main", subdir = "circuits/lib" }
```

> 📚 **For complete API documentation, see [Circuit Library Documentation](lib/README.md)**

### Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)

### Basic Usage

```rust
use zkpdf_lib::{verify_pdf_claim, PDFCircuitInput};

// Create input for PDF verification
let input = PDFCircuitInput {
    pdf_bytes: pdf_data,
    page_number: 0,
    offset: 100,
    substring: "Important Document".to_string(),
};

// Verify PDF and generate proof
let result = verify_pdf_claim(input)?;
```

## 🔧 **Running the Circuits**

### Execute the Program

To run the PDF verification without generating a proof:

```sh
cd script
cargo run --release -- --execute
```

### Generate SP1 Core Proof

To generate a core proof for PDF verification:

```sh
cd script
cargo run --release -- --prove
```

### Generate EVM-Compatible Proof

> [!WARNING]
> Requires at least 16GB RAM for Groth16/PLONK proofs.

```sh
# Groth16 proof
cd script
cargo run --release --bin evm -- --system groth16

# PLONK proof
cd script
cargo run --release --bin evm -- --system plonk
```

### Prover Server

Run the HTTP API server for remote PDF verification:

```sh
# Set environment variables
export SP1_PROVER=network
export NETWORK_PRIVATE_KEY=0x...

# Run the server
cd script
cargo run --release --bin prover
```

**API Endpoints:**

- `POST /prove` - Generate PDF verification proof
- `POST /verify` - Verify an existing proof

**Example Request:**

```json
{
  "pdf_bytes": [
    /* PDF file bytes */
  ],
  "page_number": 0,
  "sub_string": "Important Document",
  "offset": 100
}
```

### Retrieve Verification Key

```sh
cd script
cargo run --release --bin vkey
```

## 🧪 **Testing**

```bash
# Run all tests
cargo test

# Run specific circuit tests
cargo test -p zkpdf-lib
```

## 🌐 **Smart Contract Integration**

The generated proofs can be verified on-chain using the provided Solidity contracts:

```solidity
contract PdfVerifier {
    function verifyPdfProof(
        bytes calldata proof,
        bytes32 messageDigestHash,
        bytes32 signerKeyHash,
        bytes32 substringHash,
        bytes32 nullifier
    ) external view returns (bool);
}
```

## 📚 **Dependencies**

- `sp1-sdk` – SP1 zero-knowledge framework
- `pdf-utils` – PDF processing libraries
- `alloy-primitives` – Cryptographic primitives
- `serde` – Serialization framework

## 📄 **License**

This project is licensed under the same terms as the parent repository.

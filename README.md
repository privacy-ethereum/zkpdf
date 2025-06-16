# Proving PDFs in ZKP

This repository contains tools for verifying PDF documents within zero-knowledge proof systems.
Learn more in this blog post: https://pse.dev/blog/zkpdf-unlocking-verifiable-data

## Why?

Sometimes you need to prove that:

- A PDF is **signed by a trusted authority**
- A specific **text appears on a given page** without revealing the entire document.

This repo enables such proving capability using SP1-based circuits.

## Structure

- **pdf-utils/** – Rust crates for:
  - Validating PKCS#7 signatures (RSA-SHA256)
  - Extracting Unicode text from PDF streams
- **circuits/** – SP1-compatible zero-knowledge circuits for signature and text proofs
- **app/** – Minimal React frontend to demo proof generation and verification

## How it Works

1. **Parse the PDF** using pure Rust (no OpenSSL or C deps)
2. **Generate a zk proof** using SP1 circuits
3. **Verify** the proof on-chain or off-chain

## Setup

Follow these steps to run the prover API and the demo frontend.

### Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)

### 1. Clone the Repository

```bash
git clone git@github.com:privacy-scaling-explorations/zkpdf
cd zkpdf
```

### 2. Run the Prover API

Start the prover service from the `circuits/script` directory. If you have access to the Succinct Prover Network, export your API key and run:

```bash
cd circuits/script
SP1_PROVER=network \
NETWORK_PRIVATE_KEY=<PROVER_NETWORK_KEY> \
RUST_LOG=info \
cargo run --release --bin prover
```

This will start the prover API on port **3001**.

> **Note:** If you don’t have access to the Succinct Prover Network, you can omit the environment variables to run the prover locally. (This will take longer.)
>
> For local proof generation, refer to `scripts/evm.rs` or run:

```bash
RUST_LOG=info cargo run --release --bin evm -- --system groth16
```

### 3. Run the Frontend

In a separate terminal, start the Next.js app:

```bash
cd app
yarn install
yarn dev
```

Visit [http://localhost:3000](http://localhost:3000) to view the interface.



https://github.com/user-attachments/assets/2c369a52-1d2c-4487-b47d-bcb7e6ff2fec





## Use Cases

- Prove that a document is signed without showing its contents
- Selectively reveal fields from government-issued certificates
- Use verified document facts in smart contracts

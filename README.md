# Proving PDFs in ZKP

This repository collects tools for verifying PDF documents within zero-knowledge proof systems.

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

## Use Cases

- Prove that a document is signed without showing its contents
- Selectively reveal fields from government-issued certificates
- Use verified document facts in smart contracts

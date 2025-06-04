# pdf-utils

This directory collects several focused Rust crates for parsing and verifying PDFs.

> **Note**  
> This repository provides minimal, dependency-light Rust crates for working with PDFs in **zero-knowledge friendly environments**.  
> All core logic avoids heavy dependencies like `lopdf`, `flate2`, and `openssl`, making it suitable for:
>
> - Zero-knowledge virtual machines (e.g., SP1, Risc0)
> - WASM targets
> - Constrained, auditable environments

## Crates

- **`/extractor`** – Extracts plain text from PDF files. Supports:

  - Common font encodings (ToUnicode, Differences, built-in maps)
  - CID fonts and glyph name mapping
  - Minimal PDF parsing with no `lopdf` or external libraries

- **`/signature-validator`** – Verifies embedded digital signatures in PDFs using:

  - Raw PKCS#7/CMS parsing
  - Rust ASN.1 decoding
  - RSA/SHA1 and SHA2 digest verification

- **`/core`** – Combines `extractor` and `signature-validator` to:

  - Validate that specific text appears in a signed PDF
  - Check its exact byte offset on a given page
  - Return boolean results for use in proofs or UIs

- **`/wasm`** – A thin WebAssembly wrapper around the `core` crate:

## Running tests

All crates share the same workspace. Run the public tests with:

```bash
cargo test
```

Some crates have additional private tests that rely on PDF files not included in this repository. To run them, add the `private_tests` feature:

```bash
cargo test --features private_tests
```

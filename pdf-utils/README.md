# PDF Utils

A collection of lightweight Rust crates for parsing, extracting text, and verifying digital signatures in PDF documents. Designed specifically for zero-knowledge environments and constrained systems.

## 🎯 **Design Philosophy**

This repository provides minimal, dependency-light Rust crates for working with PDFs in **zero-knowledge friendly environments**. All core logic avoids heavy dependencies like `lopdf`, `flate2`, and `openssl`, making it suitable for:

- **Zero-knowledge virtual machines** (e.g., SP1, Risc0)
- **WASM targets** for web applications
- **Constrained, auditable environments** requiring minimal attack surface
- **Blockchain applications** needing PDF verification

## 📦 **Crates Overview**

### [`extractor`](./extractor/) - PDF Text Extraction

Extracts plain text from PDF files with support for:

- Common font encodings (ToUnicode, Differences, built-in maps)
- CID fonts and glyph name mapping
- Minimal PDF parsing with no external PDF libraries
- Support for StandardEncoding, WinAnsiEncoding, MacRomanEncoding, and PDFDocEncoding

### [`signature-validator`](./signature-validator/) - Digital Signature Verification

Verifies embedded digital signatures in PDFs using:

- Raw PKCS#7/CMS parsing
- Rust ASN.1 decoding
- RSA/SHA1, SHA256, SHA384, and SHA512 digest verification
- Content integrity and signature authenticity checks

### [`core`](./core/) - Combined PDF Verification

Combines `extractor` and `signature-validator` to:

- Validate that specific text appears in a signed PDF
- Check its exact byte offset on a given page
- Return boolean results for use in proofs or UIs
- Provide unified interface for PDF verification

### [`wasm`](./wasm/) - WebAssembly Interface

A thin WebAssembly wrapper around the `core` crate:

- Browser-compatible PDF verification
- JavaScript/TypeScript bindings
- Base64 PDF input/output support

## 🚀 **Quick Start**

### Basic Text Extraction

```rust
use extractor::extract_text;

let pdf_bytes = std::fs::read("document.pdf")?;
let pages = extract_text(pdf_bytes)?;
println!("Page 1: {}", pages[0]);
```

### Signature Verification

```rust
use signature_validator::verify_pdf_signature;

let pdf_bytes = std::fs::read("signed_document.pdf")?;
let is_valid = verify_pdf_signature(&pdf_bytes)?;
println!("Signature valid: {}", is_valid);
```

### Combined Verification

```rust
use core::verify_text;

let pdf_bytes = std::fs::read("document.pdf")?;
let result = verify_text(pdf_bytes, 0, "Sample Text", 100)?;
println!("Text found at position: {}", result.substring_matches);
```

## 🧪 **Testing**

All crates share the same workspace. Run the public tests with:

```bash
cargo test
```

Some crates have additional private tests that rely on PDF files not included in this repository. To run them, add the `private_tests` feature:

```bash
cargo test --features private_tests
```

Run tests for a specific crate:

```bash
cargo test -p extractor
cargo test -p signature-validator
cargo test -p core
cargo test -p wasm
```

## 📋 **Feature Support**

| Feature                          | Support |
| -------------------------------- | ------- |
| **Text Extraction**              | ✅      |
| **Font Encoding**                | ✅      |
| **Digital Signatures**           | ✅      |
| **PKCS#7/CMS**                   | ✅      |
| **Multi-page Documents**         | ✅      |
| **Compressed Streams**           | ✅      |
| **Position-based Matching**      | ✅      |
| **Combined Verification**        | ✅      |
| **WebAssembly**                  | ✅      |
| **Image Extraction**             | ❌      |
| **Form Field Processing**        | ❌      |
| **ECDSA Signatures**             | ❌      |
| **Certificate Chain Validation** | ❌      |
| **Timestamp Verification**       | ❌      |
| **Multiple Signatures**          | ❌      |
| **Complex Layout Analysis**      | ❌      |

## 🔧 **Dependencies**

- **Minimal external dependencies** - Only essential crates like `miniz_oxide`, `rsa`, `sha2`
- **No heavy PDF libraries** - Custom lightweight PDF parser
- **Zero-knowledge friendly** - All algorithms compatible with ZK-VMs
- **WASM compatible** - All crates compile to WebAssembly

## 📚 **Documentation**

Each crate has detailed documentation:

- [Extractor Documentation](./extractor/README.md)
- [Signature Validator Documentation](./signature-validator/README.md)
- [Core Documentation](./core/README.md)
- [WASM Documentation](./wasm/README.md)

## 🤝 **Contributing**

This project is designed for zero-knowledge applications. When contributing:

- Keep dependencies minimal
- Ensure ZK-VM compatibility
- Add tests for new features
- Document any breaking changes

## 📄 **License**

This project is licensed under the same terms as the parent repository.

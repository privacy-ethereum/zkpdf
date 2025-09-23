# ZKPDF Library

A Rust library for PDF verification in zero-knowledge circuits. Provides functions for text extraction, signature verification, and GST certificate processing.

## 🚀 **Quick Start**

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
zkpdf-lib = { git = "https://github.com/privacy-ethereum/zkpdf", branch = "main", subdir = "circuits/lib" }
```

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

// Verify PDF
let result = verify_pdf_claim(input)?;
```

### Complete Import Example

```rust
use zkpdf_lib::{
    // Core verification functions
    verify_pdf_claim,
    verify_gst_certificate,

    // PDF processing functions
    extract_text,
    verify_text,
    verify_and_extract,
    verify_pdf_signature,

    // Data structures
    PDFCircuitInput,
    PDFCircuitOutput,
    PdfVerificationResult,
    PdfSignatureResult,
    PublicValuesStruct,
};
```

## 📋 **API Reference**

### Core Functions

| Function                                     | Description                                         |
| -------------------------------------------- | --------------------------------------------------- |
| `verify_pdf_claim(input)`                    | Generic PDF verification with text and signature    |
| `verify_gst_certificate(input)`              | GST certificate specific verification               |
| `extract_text(pdf_bytes)`                    | Extract text from PDF pages                         |
| `verify_text(pdf_bytes, page, text, offset)` | Verify text at specific position                    |
| `verify_and_extract(pdf_bytes)`              | Combined signature verification and text extraction |
| `verify_pdf_signature(pdf_bytes)`            | Signature-only verification                         |

## 🔧 **Usage Examples**

### Basic PDF Verification

```rust
use zkpdf_lib::{verify_pdf_claim, PDFCircuitInput};

let input = PDFCircuitInput {
    pdf_bytes: std::fs::read("document.pdf")?,
    page_number: 0,
    offset: 50,
    substring: "CONFIDENTIAL".to_string(),
};

let result = verify_pdf_claim(input)?;
println!("Text found: {}", result.substring_matches);
println!("Signature valid: {}", result.signature.is_valid);
```

### GST Certificate Verification

```rust
use zkpdf_lib::{verify_gst_certificate, GSTCircuitInput};

let input = GSTCircuitInput {
    pdf_bytes: std::fs::read("gst-certificate.pdf")?,
};

let result = verify_gst_certificate(input)?;
println!("GST Number: {}", result.gst_number);
println!("Legal Name: {}", result.legal_name);
```

### Text Extraction Only

```rust
use zkpdf_lib::extract_text;

let pdf_bytes = std::fs::read("document.pdf")?;
let pages = extract_text(pdf_bytes)?;

for (i, page) in pages.iter().enumerate() {
    println!("Page {}: {}", i + 1, page);
}
```

### Signature Verification Only

```rust
use zkpdf_lib::verify_pdf_signature;

let pdf_bytes = std::fs::read("signed-document.pdf")?;
let signature_result = verify_pdf_signature(pdf_bytes)?;

if signature_result.is_valid {
    println!("Document is signed by: {}", signature_result.signer_info);
    println!("Algorithm: {}", signature_result.signature_algorithm);
}
```

## 🧪 **Testing**

```bash
# Run all tests
cargo test

# Run specific tests
cargo test -p zkpdf-lib
```

## 📚 **Dependencies**

- `pdf-utils` – PDF processing libraries
- `alloy-primitives` – Cryptographic primitives
- `serde` – Serialization framework
- `regex` – Pattern matching for text extraction

## 🔗 **Related Crates**

- `pdf-utils-core` – Core PDF verification logic
- `pdf-utils-extractor` – Text extraction from PDFs
- `pdf-utils-signature-validator` – Digital signature verification

## 📄 **License**

This crate is licensed under the same terms as the parent repository.

# API Reference

Complete reference for the ZKPDF library API with real examples from the codebase.

## API Overview

| Function                 | Purpose                                | Input                         | Output             | Use Case                                    |
| ------------------------ | -------------------------------------- | ----------------------------- | ------------------ | ------------------------------------------- |
| `verify_pdf_claim`       | Generic PDF verification               | PDFCircuitInput               | PDFCircuitOutput   | Text extraction and signature verification  |
| `verify_gst_certificate` | GST certificate verification           | PDF bytes                     | GSTCertificate     | GST number and legal name extraction        |
| `verify_text`            | Text verification at specific location | PDF bytes, page, offset, text | Boolean            | Verify text appears at exact position       |
| `verify_and_extract`     | Simple verification and extraction     | PDF bytes                     | VerificationResult | Basic PDF verification with text extraction |
| `extract_text`           | Text extraction only                   | PDF bytes                     | Vec<String>        | Extract all text from PDF pages             |
| `verify_signature`       | Signature verification only            | PDF bytes                     | SignatureResult    | Validate digital signatures                 |

## Core Functions

### `verify_pdf_claim`

Generic PDF verification function for text extraction and signature verification in zero-knowledge circuits.

```rust
pub fn verify_pdf_claim(input: PDFCircuitInput) -> Result<PDFCircuitOutput, String>
```

**Parameters:**

- `input: PDFCircuitInput` - Input containing PDF bytes and verification parameters

**Returns:**

- `Result<PDFCircuitOutput, String>` - Verification result or error message

**Example from circuits/script/src/bin/main.rs:**

```rust
use zkpdf_lib::{types::PDFCircuitInput, verify_pdf_claim};

// Load PDF from file
let pdf_bytes = std::fs::read("digitally_signed.pdf")
    .expect("Failed to read PDF file");

let proof_input = PDFCircuitInput {
    pdf_bytes,
    page_number: 0,
    offset: 0,
    substring: "Sample Signed PDF Document".to_string(),
};

let result = verify_pdf_claim(proof_input)?;
```

### `verify_gst_certificate`

GST certificate specific verification that extracts GST number and legal name using regex patterns.

```rust
pub fn verify_gst_certificate(pdf_bytes: Vec<u8>) -> GSTCertificate
```

**Parameters:**

- `pdf_bytes: Vec<u8>` - PDF file bytes

**Returns:**

- `GSTCertificate` - Structure containing GST number, legal name, and signature

**Example from circuits/lib/src/gst_example.rs:**

```rust
use zkpdf_lib::verify_gst_certificate;

let pdf_bytes = std::fs::read("gst_certificate.pdf")?;
let gst_cert = verify_gst_certificate(pdf_bytes);

println!("GST Number: {}", gst_cert.gst_number);
println!("Legal Name: {}", gst_cert.legal_name);
println!("Signature Valid: {}", gst_cert.signature.is_valid);
```

### `extract_text`

Extract text from PDF pages without verification (from pdf_core crate).

```rust
pub fn extract_text(pdf_bytes: Vec<u8>) -> Result<Vec<String>, String>
```

**Parameters:**

- `pdf_bytes: Vec<u8>` - PDF file bytes

**Returns:**

- `Result<Vec<String>, String>` - Vector of page text or error message

**Example:**

```rust
use zkpdf_lib::extract_text;

let pdf_bytes = std::fs::read("document.pdf")?;
let pages = extract_text(pdf_bytes)?;

for (i, page) in pages.iter().enumerate() {
    println!("Page {}: {}", i + 1, page);
}
```

### `verify_text`

Verify text at specific position with signature validation (from pdf_core crate).

```rust
pub fn verify_text(
    pdf_bytes: Vec<u8>,
    page_number: u8,
    substring: &str,
    offset: usize
) -> Result<PdfVerificationResult, String>
```

**Parameters:**

- `pdf_bytes: Vec<u8>` - PDF file bytes
- `page_number: u8` - Page number (0-indexed)
- `substring: &str` - Text to search for
- `offset: usize` - Byte offset to start search

**Returns:**

- `Result<PdfVerificationResult, String>` - Verification result with text matches and signature

**Example usage in verify_pdf_claim:**

```rust
use zkpdf_lib::verify_text;

// From circuits/lib/src/lib.rs
let result = verify_text(pdf_bytes, page_number, substring.as_str(), offset as usize)?;
```

### `verify_pdf_signature`

Signature-only verification (from signature_validator crate).

```rust
pub fn verify_pdf_signature(pdf_bytes: Vec<u8>) -> Result<PdfSignatureResult, String>
```

**Parameters:**

- `pdf_bytes: Vec<u8>` - PDF file bytes

**Returns:**

- `Result<PdfSignatureResult, String>` - Signature verification result or error message

**Example:**

```rust
use zkpdf_lib::verify_pdf_signature;

let signature_result = verify_pdf_signature(pdf_bytes)?;

if signature_result.is_valid {
    println!("Document is signed by: {}", signature_result.signer_info);
    println!("Algorithm: {}", signature_result.signature_algorithm);
}
```

### `verify_and_extract`

Combined verification and extraction in one call (from pdf_core crate).

```rust
pub fn verify_and_extract(pdf_bytes: Vec<u8>) -> Result<PdfVerifiedContent, String>
```

**Parameters:**

- `pdf_bytes: Vec<u8>` - PDF file bytes

**Returns:**

- `Result<PdfVerifiedContent, String>` - Verified content with pages and signature

**Example from GST verification:**

```rust
use zkpdf_lib::verify_and_extract;

// From circuits/lib/src/gst_example.rs
let verified_content = verify_and_extract(pdf_bytes).unwrap();
let full_text = verified_content.pages.join(" ");
// Extract specific patterns from full_text...
```

## Data Structures

### `PDFCircuitInput`

Input structure for PDF verification circuits (from types.rs).

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDFCircuitInput {
    pub pdf_bytes: Vec<u8>,
    pub page_number: u8,
    pub offset: u32,
    pub substring: String,
}
```

**Fields:**

- `pdf_bytes: Vec<u8>` - PDF file bytes
- `page_number: u8` - Page number (0-indexed)
- `offset: u32` - Byte offset for text verification
- `substring: String` - Text substring to verify

### `PDFCircuitOutput`

Output structure for PDF verification circuits (from types.rs).

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDFCircuitOutput {
    // Output details are handled internally by PublicValuesStruct
}
```

### `GSTCertificate`

Structure for GST certificate verification results (from gst_example.rs).

```rust
pub struct GSTCertificate {
    pub gst_number: String,
    pub legal_name: String,
    pub signature: PdfSignatureResult,
}
```

**Fields:**

- `gst_number: String` - Extracted GST number using regex pattern
- `legal_name: String` - Legal name of the business
- `signature: PdfSignatureResult` - Signature verification result

### `PublicValuesStruct`

Public values structure for zero-knowledge circuit outputs (from types.rs).

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicValuesStruct {
    pub substringMatches: bool,
    pub messageDigestHash: [u8; 32],
    pub signerKeyHash: [u8; 32],
    pub substringHash: [u8; 32],
    pub nullifier: [u8; 32],
}
```

**Fields:**

- `substringMatches: bool` - Whether the substring was found
- `messageDigestHash: [u8; 32]` - Hash of the message digest
- `signerKeyHash: [u8; 32]` - Hash of the signer's public key
- `substringHash: [u8; 32]` - Hash of the substring
- `nullifier: [u8; 32]` - Nullifier for privacy

### `PdfVerificationResult`

Result structure for PDF text verification.

```rust
#[derive(Debug, Clone)]
pub struct PdfVerificationResult {
    pub substring_matches: Vec<usize>,
    pub page_text: String,
    pub verification_successful: bool,
}
```

**Fields:**

- `substring_matches: Vec<usize>` - Byte offsets where substring was found
- `page_text: String` - Extracted text from the page
- `verification_successful: bool` - Whether verification was successful

### `PdfSignatureResult`

Result structure for PDF signature verification.

```rust
#[derive(Debug, Clone)]
pub struct PdfSignatureResult {
    pub is_valid: bool,
    pub signer_info: String,
    pub signature_algorithm: String,
    pub signing_time: u64,
    pub certificate_info: String,
}
```

**Fields:**

- `is_valid: bool` - Whether the signature is valid
- `signer_info: String` - Information about the signer
- `signature_algorithm: String` - Algorithm used for signing
- `signing_time: u64` - Timestamp of signing
- `certificate_info: String` - Certificate information

### `PublicValuesStruct`

Public values structure for circuit outputs.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicValuesStruct {
    pub result: bool,
}
```

**Fields:**

- `result: bool` - Boolean result of the verification

## Error Types

### Common Error Messages

- `"PDF parsing failed"` - PDF file could not be parsed
- `"Text not found"` - Specified text was not found
- `"Invalid signature"` - PDF signature is invalid
- `"Page not found"` - Specified page number is out of range
- `"Offset out of range"` - Specified offset is beyond page content
- `"Serialization error"` - Error serializing input data
- `"Deserialization error"` - Error deserializing output data

## WebAssembly API

### JavaScript Bindings

The WASM module provides JavaScript bindings for browser usage:

```javascript
// Initialize the WASM module
import init, { verify_pdf_claim } from "./pkg/wasm.js";

await init();

// Verify PDF in browser
function verifyPDFInBrowser(pdfBytes, pageNumber, substring, offset) {
  try {
    const result = verify_pdf_claim(pdfBytes, pageNumber, substring, offset);
    return {
      success: true,
      result: result,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}
```

### TypeScript Definitions

```typescript
interface PDFCircuitInput {
  pdf_bytes: Uint8Array;
  page_number: number;
  offset: number;
  substring: string;
}

interface PDFCircuitOutput {
  substring_matches: number[];
  page_number: number;
  offset: number;
  signature: PdfSignatureResult;
}

interface PdfSignatureResult {
  is_valid: boolean;
  signer_info: string;
  signature_algorithm: string;
  signing_time: number;
  certificate_info: string;
}

declare function verify_pdf_claim(input: PDFCircuitInput): PDFCircuitOutput;
declare function extract_text(pdf_bytes: Uint8Array): string[];
declare function verify_pdf_signature(
  pdf_bytes: Uint8Array
): PdfSignatureResult;
```

## Next Steps

- **[Examples](examples.md)**: Practical usage examples
- **[FAQ](faq.md)**: Common questions and answers
- **[Proving](proving.md)**: Generate proofs from your circuits
- **[Verification](verification.md)**: Verify proofs on-chain

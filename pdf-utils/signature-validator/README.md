# PDF Digital Signature Validator

A lightweight Rust crate for verifying digital signatures in PDF documents. Designed for zero-knowledge environments with minimal dependencies and comprehensive PKCS#7/CMS support.

## 🎯 **Overview**

The `signature-validator` crate provides robust verification of digital signatures embedded in PDF files. It focuses on signatures within **PKCS#7/CMS SignedData structures** and performs both content integrity and signature authenticity checks.

## 🚀 **Quick Start**

```rust
use signature_validator::verify_pdf_signature;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read signed PDF file
    let pdf_bytes = std::fs::read("signed_document.pdf")?;

    // Verify the signature
    let result = verify_pdf_signature(&pdf_bytes)?;

    if result.is_valid {
        println!("✅ Signature is valid!");
        println!("Signer: {}", result.signer_info);
        println!("Signing time: {}", result.signing_time);
    } else {
        println!("❌ Signature verification failed");
    }

    Ok(())
}
```

## 📋 **Main Interface**

```rust
pub fn verify_pdf_signature(pdf_bytes: &[u8]) -> Result<PdfSignatureResult, String>
```

**Parameters:**

- `pdf_bytes`: Raw PDF file bytes

**Returns:**

- `Ok(PdfSignatureResult)`: Detailed signature verification result
- `Err(String)`: Error if verification fails

### Signature Result Structure

```rust
pub struct PdfSignatureResult {
    pub is_valid: bool,                    // Overall verification result
    pub message_digest: Vec<u8>,           // Extracted message digest
    pub public_key: Vec<u8>,               // Signer's public key
    pub signer_info: String,               // Signer information
    pub signing_time: Option<String>,      // Signing timestamp
    pub signature_algorithm: String,        // Used signature algorithm
}
```

## 🔐 **Verification Process**

The `verify_pdf_signature` function performs two critical checks:

### 1. **Content Integrity Check**

Verifies that the PDF content hasn't been tampered with since signing.

**Process:**

1. Extract `signed_bytes` from PDF using the `ByteRange`
2. Calculate cryptographic hash using the specified algorithm
3. Compare with stored `MessageDigest` value

**Mathematical Verification:**

```
Hash(signed_bytes) == MessageDigest
```

### 2. **Signature Authenticity Check**

Verifies that the signature was created by the claimed signer.

**Process:**

1. Extract `signed_attributes` (ASN.1 structure)
2. Hash the encoded signed attributes
3. Verify signature using signer's public key

**Mathematical Verification:**

```
Verify(PublicKey, Hash(signed_attributes), Signature) == true
```

## 📄 **How PDF Signatures Work**

### ByteRange Concept

PDF signatures don't cover the entire file. Instead, they sign specific byte ranges:

- **`ByteRange`** defines which parts of the PDF were signed
- Typically includes document content and metadata
- Excludes the signature field itself and later additions
- Allows incremental updates without invalidating signatures

### Signed Attributes Structure

```asn1
SET {
    OBJECT IDENTIFIER (messageDigest)
    OCTET STRING (hash value)
    OBJECT IDENTIFIER (signingTime)
    UTCTime (time value)
    OBJECT IDENTIFIER (contentType)
    OBJECT IDENTIFIER (signingCertificate)
    ...
}
```

## 🔧 **Supported Algorithms**

| Algorithm      | Hash Function | Encryption | Support |
| -------------- | ------------- | ---------- | ------- |
| **RSA-SHA1**   | SHA-1         | RSA        | ✅      |
| **RSA-SHA256** | SHA-256       | RSA        | ✅      |
| **RSA-SHA384** | SHA-384       | RSA        | ✅      |
| **RSA-SHA512** | SHA-512       | RSA        | ✅      |

### Algorithm Details

- **Hash Functions**: SHA-1, SHA-256, SHA-384, SHA-512
- **Encryption**: RSA with PKCS#1 v1.5 padding
- **Signature Format**: PKCS#7/CMS SignedData
- **ASN.1 Encoding**: DER (Distinguished Encoding Rules)

## 📝 **Usage Examples**

### Basic Signature Verification

```rust
use signature_validator::verify_pdf_signature;

let pdf_bytes = include_bytes!("document.pdf");
let result = verify_pdf_signature(pdf_bytes)?;

if result.is_valid {
    println!("Document is authentic and unmodified");
} else {
    println!("Document verification failed");
}
```

### Detailed Signature Information

```rust
let result = verify_pdf_signature(&pdf_bytes)?;

println!("Signature Valid: {}", result.is_valid);
println!("Algorithm: {}", result.signature_algorithm);
println!("Signer: {}", result.signer_info);

if let Some(time) = result.signing_time {
    println!("Signed at: {}", time);
}

// Access raw cryptographic data
println!("Message Digest: {}", hex::encode(&result.message_digest));
println!("Public Key Length: {} bytes", result.public_key.len());
```

### Core Components

- **PDF Parser** – Extracts signature fields and ByteRange
- **PKCS#7 Parser** – Parses ASN.1 SignedData structures
- **Crypto Engine** – Performs hash and signature verification
- **Certificate Handler** – Processes signer certificates

### Dependencies

- `rsa` – RSA signature verification
- `sha1`, `sha2` – Hash function implementations
- `simple_asn1` – ASN.1 parsing
- `hex` – Hexadecimal encoding/decoding
- `num-bigint` – Big integer arithmetic for RSA

## 🧪 **Testing**

### Public Tests

Run the basic test suite:

```bash
cargo test -p signature-validator
```

### Private Tests

Run tests with sample signed PDFs:

```bash
cargo test -p signature-validator --features private_tests
```

## ⚠️ **Limitations**

### Supported Features

- ✅ PKCS#7/CMS SignedData structures
- ✅ RSA signatures with SHA-1/256/384/512
- ✅ Standard PDF signature fields
- ✅ ByteRange-based content verification
- ✅ ASN.1 DER encoding

### Unsupported Features

- ❌ ECDSA signatures
- ❌ Timestamp verification
- ❌ Certificate chain validation and Multiple signatures

## 🤝 **Contributing**

When contributing to the signature validator:

- Keep dependencies minimal
- Ensure ZK-VM compatibility
- Add tests for new algorithms
- Document security considerations
- Maintain compatibility with existing signatures

## 📄 **License**

This crate is licensed under the same terms as the parent repository.

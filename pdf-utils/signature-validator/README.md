# signature-verifier

`signature-verifier` is a simple Rust crate that checks if the digital signatures in PDF files are valid. It focuses on signatures embedded within **PKCS#7/CMS SignedData structures**.

## Main Interface

The primary function is `verify_pdf_signature`:

```rust
pub fn verify_pdf_signature(pdf_bytes: &[u8]) -> Result<bool, String>
```

It takes the raw bytes of a PDF file and returns `Ok(true)` if the verification is valid, `Ok(false)` if invalid, and `Err(String)` if an error occurred.

### Running tests

**1. Public Test:**

To run the basic test, use this command:

```bash
cargo test
```

**2. Private Test:**

It contains private test cases that are not exposed to the public. To run these tests, use the following command:

```bash
cargo test --features private_tests
```

---

## Verification Process

`verify_pdf_signature` function performs two main checks:

1. **Content Integrity Check**
2. **Signature Authenticity Check**

### How Signed Data Works in PDFs

When a PDF is digitally signed, the signature typically doesn't cover the entire file. Instead, a specific portion of the PDF's data, defined by the **`ByteRange`**, is cryptographically signed. This `ByteRange` usually includes the document's main content and relevant metadata.

Within the PDF:

- The **`ByteRange`** specifies the exact byte sequences that were included in the signing process.
- During verification, only these byte ranges are read and processed; other parts of the PDF, such as the signature field itself or later additions like timestamps, are excluded from the initial integrity check.

---

## Content Integrity Check (Message Digest)

Here's the process:

- Extract the `signed_bytes` from the PDF using the `ByteRange`.
- Calculate the cryptographic hash of these bytes using the algorithm specified in the signature. Let's denote the hash function as \( H \).
- Retrieve the `MessageDigest` value (\( M \)) stored within the PDF's signature dictionary.

The verification then involves checking the following equation:

```math
Hash(\text{signed\_bytes}) == M
```

## Signature Authenticity Check

After Content Integrity Check, the actual digital signature is verified. This signature covers a data structure known as `signed_attributes`, which is typically an ASN.1 structure embedded within the PDF.

### What are signed_attributes?

These are structured data, often represented as an ASN.1 `SET`. It contain critical metadata associated with the signing event, including the MessageDigest, the time of signing, and potentially other relevant information.
Before the digital signature is generated, these signed_attributes are encoded and then cryptographically hashed.

```asn1
SET {
    OBJECT IDENTIFIER (messageDigest)
    OCTET STRING (hash value)
    OBJECT IDENTIFIER (signingTime)
    UTCTime (time value)
    ...
}
```

---

### Signature Verification Process:

( H(\text{signed_attributes}) ) as the cryptographic hash of the encoded signed_attributes.
( Sig ) as the digital signature extracted from the PDF.
( PK ) as the public key associated with the signer's certificate.

Then we verify:
\text{Verify}(PK, H(\text{signed_attributes}), Sig) == \text{true}
If:

## Supported Algorithms (PKCS#7 with RSA)

This crate currently supports verification for PDF signatures using **PKCS#7/CMS SignedData** structures with the following algorithms:

| Algorithm                   | Support |
| --------------------------- | ------- |
| SHA-1 with RSA encryption   | Yes     |
| SHA-256 with RSA encryption | Yes     |
| SHA-384 with RSA encryption | Yes     |
| SHA-512 with RSA encryption | Yes     |

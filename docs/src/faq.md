# FAQ

Frequently asked questions about ZKPDF, covering common issues, troubleshooting, and best practices.

## General Questions

### What is ZKPDF?

ZKPDF is a zero-knowledge proof system for verifying PDF documents. It allows you to cryptographically prove properties about PDFs (like specific text appearing at exact positions or valid digital signatures) without revealing the entire document content.

### What are the main use cases for ZKPDF?

- **Document Authentication**: Prove a document is signed by a trusted authority
- **Selective Disclosure**: Reveal specific fields from government-issued certificates
- **Smart Contract Integration**: Use verified document facts in blockchain applications
- **Fraud Prevention**: Detect if documents have been tampered with
- **Compliance**: Meet regulatory requirements for document verification

### Is ZKPDF production-ready?

ZKPDF is actively developed and used in production environments. However, it's important to:

- Test thoroughly with your specific PDF types
- Understand the limitations (see [Architecture](architecture.md))
- Implement proper error handling
- Consider performance implications for large documents

## Technical Questions

### What PDF formats are supported?

ZKPDF supports standard PDF files with the following features:

- ✅ Text extraction from PDF streams
- ✅ Digital signatures (RSA-SHA256, SHA384, SHA512)
- ✅ Multi-page documents
- ✅ Compressed streams
- ❌ Images (extraction not supported)
- ❌ Form fields
- ❌ ECDSA signatures
- ❌ Complex layouts

### How accurate is text extraction?

Text extraction accuracy depends on:

- **Font encoding**: Better accuracy with standard encodings
- **PDF structure**: Well-structured PDFs extract more accurately
- **Font types**: Some custom fonts may not extract perfectly
- **Layout complexity**: Simple layouts extract better than complex ones

### What signature algorithms are supported?

Currently supported:

- ✅ RSA-SHA256
- ✅ RSA-SHA384
- ✅ RSA-SHA512
- ❌ ECDSA signatures
- ❌ DSA signatures

### How do I check if my PDF is compatible with ZKPDF?

Use the **ZKPDF Compatibility Checker** to verify if your PDF will work with zkPDF:

🔗 **[https://privacy-ethereum.github.io/zkpdf/](https://privacy-ethereum.github.io/zkpdf/)**

Simply drop your PDF file into the compatibility checker to:

- ✅ Verify digital signature compatibility
- ✅ Check PDF structure and format
- ✅ Test text extraction capabilities
- ✅ Validate signature algorithms

This tool helps you determine if your PDF will work with zkPDF before implementing it in your application.

### How do I handle different PDF generators?

Different PDF generators may produce different byte layouts. To handle this:

1. **Use offset ranges** instead of exact offsets
2. **Test with multiple PDF generators**
3. **Use signature verification** for authenticity
4. **Implement fallback strategies**

```rust
// Instead of exact offset
let result = verify_text(pdf_bytes, 0, "CONFIDENTIAL", 100)?;

// Use offset range
let result = verify_text_range(pdf_bytes, 0, "CONFIDENTIAL", 90, 110)?;
```

### Can I run ZKPDF on client-side mobile or browser?

**No, you cannot run ZKPDF on client-side mobile or browser.** ZKPDF is computationally heavy and requires significant resources that are not available in mobile browsers or client-side environments. The zero-knowledge proof generation process involves:

- **Heavy cryptographic computations** requiring substantial CPU power
- **Large memory requirements** (hundreds of MB to GB)
- **Complex PDF parsing** and signature verification
- **Proof generation** that takes 30-60 seconds even on powerful servers

**Recommended approach**: Use server-side proving with the Succinct Prover Network or your own server infrastructure, then verify proofs on-chain or through API calls.

## Integration Questions

### How do I integrate ZKPDF with my application?

Integration depends on your use case:

1. **Rust applications**: Use the library directly
2. **Web applications**: Use WASM bindings
3. **Node.js applications**: Use the prover API
4. **Smart contracts**: Deploy verification contracts

### Can I use ZKPDF with other blockchain networks?

Yes, ZKPDF proofs can be verified on any network that supports the SP1 verifier:

- ✅ Ethereum
- ✅ Polygon
- ✅ Arbitrum
- ✅ Optimism
- ✅ Other EVM-compatible networks

### How do I deploy verification contracts?

1. **Deploy SP1 verifier** (if not already deployed)
2. **Get program verification key**
3. **Deploy PdfVerifier contract**
4. **Test with sample proofs**

```bash
# Deploy contract
forge create --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  src/PdfVerifier.sol:PdfVerifier \
  --constructor-args $SP1_VERIFIER_ADDRESS $PROGRAM_VKEY
```

### What if I need to support new PDF features?

ZKPDF is designed to be extensible:

1. **Fork the repository**
2. **Add new features** to pdf-utils
3. **Update circuits** if needed
4. **Submit pull request**

## License Questions

### What license does ZKPDF use?

ZKPDF is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

### Can I use ZKPDF commercially?

Yes, the MIT License allows commercial use with minimal restrictions.

### Do I need to attribute ZKPDF?

While not required, attribution is appreciated. You can include:

```markdown
This project uses ZKPDF for PDF verification.
https://github.com/privacy-ethereum/zkpdf
```

## Next Steps

- **[Examples](examples.md)**: Practical usage examples
- **[API Reference](api-reference.md)**: Complete API documentation
- **[Proving](proving.md)**: Generate proofs from your circuits
- **[Verification](verification.md)**: Verify proofs on-chain

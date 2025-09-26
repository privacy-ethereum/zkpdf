# Introduction to ZKPDF

ZKPDF is a library that enables you to create zero-knowledge proofs about data contained within PDF documents. It allows you to cryptographically prove properties about PDFs without revealing their full contents, making it particularly useful for verifying digital signatures and proving that specific statements appear in documents.

*Note: The current implementation exposes data to SP1's prover network; therefore, we highly recommend only using the provided PDF templates for testing. Future iterations will focus on client-side proofing capabilities. 

## Quick Links

- 🔗 **[ZKPDF Compatibility Checker](https://privacy-ethereum.github.io/zkpdf/)** - Test if your PDF works with zkPDF
- 🚀 **[zkPDF Template](https://github.com/privacy-ethereum/zkpdf-template)** - Ready-to-use template with GST certificate example
- 📚 **[Blog Post](https://pse.dev/blog/zkpdf-unlocking-verifiable-data)** - Learn how signed data becomes SNARKed
- 🌐 **[Succinct Prover Network](https://forms.gle/aqVoYupq3cjNYtCf8)** - Access form for hackathon proving
- 📖 **[API Reference](api-reference.md)** - Complete function documentation
- ⚡ **[Quick Start](quick-start.md)** - Get up and running in minutes

## The Ever-Expanding Ecosystem of Signed Data

We've already made remarkable progress in "SNARKifying" various forms of signed data. The ability to cryptographically verify information while preserving privacy can be used in real-world applications at scale. Consider what is actively in use today:

- **ZK-Email**: Email verification, allowing users to prove specific facts about email content without revealing the email itself
- **National Identity Cards**: India's Aadhaar program has over 1.4 billion digital identities, Projects like Anon Aadhaar allows users to prove they have a valid Aadhaar card and are over 18 without revealing their identity number, name, or other personal details
- **Electronic Passports (zkpassport)**: There are 1.2+ billion e-passports in global circulation, each containing cryptographically signed biometric data that prevents forgery and identity theft at borders—a testament to worldwide adoption of verifiable physical documents
- **Web Data (zkTLS)**: Emerging technologies like zkTLS allow users to prove specific content on a website

### The PDF Gap

The PDF Association estimates that "well over 90 percent of all signed documents are PDFs," with the e-signature market projected to grow at over 25% annually through 2025, representing a substantial volume of signed data.

ZKPDF bridges this critical gap, bringing the power of zero-knowledge verification to the world's most popular document format.

## What ZKPDF Does

ZKPDF abstracts away all the complex PDF parsing, signature validation, and cryptographic proof generation. You simply provide a PDF and specify what you want to prove—zkPDF handles all the technical complexity behind the scenes.

The library focuses on three core capabilities:

- **Digital Signature Verification**: Prove that a PDF contains a valid digital signature from a trusted authority
- **Content Verification**: Prove that specific text appears at exact locations within a PDF document
- **Privacy-Preserving Verification**: Verify document properties without exposing sensitive content

**You don't need to understand PDF parsing, PKCS#7 structures, or zero-knowledge circuits, zkPDF abstracts all of this complexity into simple, easy-to-use APIs.**

## Real-World Applications

- **Financial Services**: Bank statements, tax documents, insurance claims
- **Government & Compliance**: Identity documents, business certificates, legal documents
- **Healthcare**: Medical records, vaccination status, insurance verification

## How Signed Data Becomes SNARKed

_This section explains what happens under the hood when you use zkPDF—you don't need to implement any of this yourself._

The process of converting signed PDF data into zero-knowledge proofs involves several key steps that zkPDF handles automatically:

### 1. PDF Parsing and Signature Extraction

ZKPDF uses pure Rust libraries to parse PDF documents and extract embedded digital signatures. This includes:

- Parsing PKCS#7/CMS signature structures
- Extracting certificate chains and signature metadata
- Validating signature integrity using cryptographic hash functions
- Supporting various signature algorithms (RSA-SHA256, RSA-SHA1)
- Handling complex PDF layouts and embedded fonts

### 2. Content Verification

The library can verify that specific text appears at precise byte offsets within the PDF:

- Extracts Unicode text from PDF streams using custom font encoding support
- Tracks exact positions of text elements on specific pages
- Validates that claimed content matches the actual document structure
- Handles various PDF text encodings and font mappings

### 3. Zero-Knowledge Proof Generation

Using SP1 circuits, ZKPDF generates cryptographic proofs that demonstrate:

- The PDF contains a valid digital signature from a trusted certificate authority
- The signature was created by the claimed signer
- Specific text appears at the claimed location within the document
- All verification was performed correctly without revealing the full document content

## Features

- **No External Dependencies**: Pure Rust implementation without OpenSSL or C libraries
- **Browser Compatible**: WebAssembly support for client-side processing
- **Cross-Platform**: Works across different operating systems and environments
- **EVM Compatible**: Generated proofs can be verified on Ethereum and other EVM-compatible chains

## Key Benefits

- **Privacy**: Verify document properties without exposing sensitive content
- **Trust**: Cryptographic guarantees about document authenticity and content
- **Efficiency**: Lightweight verification suitable for blockchain applications
- **Flexibility**: Works with various PDF types and signature schemes
- **Selective Disclosure**: Prove only the specific information you need to reveal
- **Tamper Evidence**: Any modification to the document invalidates the proof

## Learn More

For a deeper dive into ZKPDF's capabilities, technical implementation, and real-world use cases, read our comprehensive blog post: [ZKPDF: Unlocking Verifiable Data in the World's Most Popular Document Format](https://pse.dev/blog/zkpdf-unlocking-verifiable-data)

The blog post covers:

- Detailed technical architecture and implementation
- Real-world case studies and applications
- Performance benchmarks and optimization strategies
- Integration patterns for different blockchain networks

## Next Steps

- **[Quick Start](quick-start.md)**: Get up and running in minutes
- **[API Reference](api-reference.md)**: Complete function documentation
- **[Proving](proving.md)**: Set up proof generation workflows
- **[On-chain Verification](verification.md)**: Integrate blockchain verification

# PDF Verification Demo

A Next.js frontend for demonstrating PDF verification and zero-knowledge proof generation.

## 🚀 **Quick Start**

```bash
# Build WASM module first (requires Rust + wasm-pack)
cd ../pdf-utils/wasm && ./generate_wasm.sh && cd ../../app

# Install dependencies
yarn install

# Start development server
yarn dev
```

Open [http://localhost:3000](http://localhost:3000) to view the demo.

## 🔧 **Features**

- Upload PDF documents
- Verify digital signatures
- Generate zero-knowledge proofs
- Extract text from PDFs
- Real-time verification results

## 📋 **Requirements**

- [Rust](https://rustup.rs/)
- [Node.js 18+](https://nodejs.org/)
- Running prover server (see [circuits/README.md](../circuits/README.md))

## 🌐 **API Integration**

The app connects to the prover server running on port 3001 for PDF verification and proof generation.

## 📄 **License**

This project is licensed under the same terms as the parent repository.

# ZKPDF Documentation

This directory contains the complete documentation for the ZKPDF library - a zero-knowledge proof system for verifying PDF documents.

## 📚 Documentation Structure

- **[Introduction](src/introduction.md)** - Overview of ZKPDF, how it works, limitations, and architecture
- **[Quick Start](src/quick-start.md)** - Get started with ZKPDF in minutes
- **[Architecture](src/architecture.md)** - Detailed architecture overview
- **[Custom Circuits](src/custom-circuits.md)** - Building custom verification circuits and examples
- **[Proving](src/proving.md)** - Server-side proving workflows and succinct keys setup
- **[Verification](src/verification.md)** - On-chain proof verification and smart contract integration
- **[Examples](src/examples.md)** - Comprehensive usage examples
- **[API Reference](src/api-reference.md)** - Complete API documentation
- **[FAQ](src/faq.md)** - Frequently asked questions

## 🔗 External Resources

- **Compatibility Check**: [https://privacy-ethereum.github.io/zkpdf/](https://privacy-ethereum.github.io/zkpdf/)
- **GitHub Repository**: [https://github.com/privacy-ethereum/zkpdf](https://github.com/privacy-ethereum/zkpdf)
- **Blog Post**: [ZKPDF: Unlocking Verifiable Data](https://pse.dev/blog/zkpdf-unlocking-verifiable-data)

## 🛠️ Building the Documentation

This documentation is built using [mdBook](https://rust-lang.github.io/mdBook/). To build and serve locally:

```bash
# Install mdbook
cargo install mdbook

# Build the documentation
./build.sh

# Serve locally
mdbook serve
```

The documentation will be available at `http://localhost:3000`.

## 📝 Contributing

To contribute to the documentation:

1. Fork the repository
2. Create a feature branch
3. Make your changes in the `src/` directory
4. Test your changes with `mdbook serve`
5. Submit a pull request

## 📄 License

This documentation is licensed under the same terms as the ZKPDF project.

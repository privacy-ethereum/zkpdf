# PDF Text Extractor

A lightweight Rust crate for extracting plain text from PDF documents. Designed for zero-knowledge environments with minimal dependencies.

## 🎯 **Overview**

The `extractor` crate provides a simple, dependency-light solution for reading textual content from PDF files. It implements a minimal subset of PDF text extraction rules without relying on heavy external libraries like `lopdf` or `flate2`.

## 🚀 **Quick Start**

```rust
use extractor::extract_text;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read PDF file
    let pdf_bytes = std::fs::read("document.pdf")?;

    // Extract text from all pages
    let pages = extract_text(pdf_bytes)?;

    // Print text from each page
    for (i, page_text) in pages.iter().enumerate() {
        println!("Page {}: {}", i + 1, page_text);
    }

    Ok(())
}
```

## 📋 **Main Interface**

```rust
pub fn extract_text(pdf_bytes: Vec<u8>) -> Result<Vec<String>, PdfError>
```

**Parameters:**

- `pdf_bytes`: Raw PDF file bytes

**Returns:**

- `Ok(Vec<String>)`: Vector of strings, one per page
- `Err(PdfError)`: Error if extraction fails

## 🔤 **Encoding & Font Support**

The extractor supports a comprehensive set of font encodings commonly used in PDF documents:

### Supported Encodings

- **StandardEncoding** – Adobe's base Latin encoding (ISO 8859-1 subset)
- **WinAnsiEncoding** – Windows-1252 encoding
- **MacRomanEncoding** – Classic Mac OS encoding
- **MacExpertEncoding** – Extended Mac encoding for typography
- **PDFDocEncoding** – Default encoding for PDF strings

### Font Features

- **Glyph name mapping** – Converts font glyph names to Unicode characters
- **CID font support** – Handles Composite Font (CID) structures
- **ToUnicode mapping** – Supports Unicode character mapping tables
- **Font differences** – Handles custom character substitutions

### Character Coverage

The extractor includes a comprehensive lookup table for common glyph names, supporting:

- Latin characters (A-Z, a-z)
- Accented characters (é, ñ, ü, etc.)
- Special symbols (©, ®, ™, etc.)
- Mathematical symbols (×, ÷, ±, etc.)
- Currency symbols (€, £, ¥, etc.)

## 🏗️ **Architecture**

### Core Components

- **PDF Parser** – Lightweight PDF structure parser
- **Font Decoder** – Font encoding and glyph mapping
- **Text Stream Processor** – Extracts text from PDF streams
- **Decompression** – Handles zlib/deflate compression

### Dependencies

- `miniz_oxide` – Pure Rust zlib/deflate decompression
- No external PDF libraries
- Zero-knowledge VM compatible

## 📝 **Usage Examples**

### Basic Text Extraction

```rust
use extractor::extract_text;

let pdf_bytes = include_bytes!("sample.pdf");
let pages = extract_text(pdf_bytes.to_vec())?;
println!("Extracted {} pages", pages.len());
```

### Working with Specific Pages

```rust
let pages = extract_text(pdf_bytes)?;

// Get first page
if let Some(first_page) = pages.first() {
    println!("First page: {}", first_page);
}

// Get last page
if let Some(last_page) = pages.last() {
    println!("Last page: {}", last_page);
}

// Check if specific text exists
let search_text = "Important Document";
let found = pages.iter().any(|page| page.contains(search_text));
println!("Text found: {}", found);
```

## 🧪 **Testing**

### Public Tests

Run the basic test suite:

```bash
cargo test -p extractor
```

### Private Tests

Run tests with sample PDF files:

```bash
cargo test -p extractor --features private_tests
```

## ⚠️ **Limitations**

### Supported PDF Features

- ✅ Simple text extraction
- ✅ Common font encodings
- ✅ Basic compression (zlib/deflate)
- ✅ Standard PDF structure

### Unsupported Features

- ❌ Image or graphics extraction
- ❌ Form field extraction
- ❌ Advanced font features (ligatures, kerning)
- ❌ PDF/A or PDF/X specific features

## 🤝 **Contributing**

When contributing to the extractor:

- Keep dependencies minimal
- Ensure ZK-VM compatibility
- Add tests for new encodings
- Document any breaking changes
- Maintain performance for simple PDFs

## 📄 **License**

This crate is licensed under the same terms as the parent repository.

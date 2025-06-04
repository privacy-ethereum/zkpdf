# extractor

`extractor` is a small Rust crate that reads textual content from PDF files.

## Main Interface

```rust
pub fn extract_text(pdf_bytes: Vec<u8>) -> Result<Vec<String>, PdfError>
```

This function returns a list of strings containing the text for each page of the PDF.

## Encoding & Glyph Support

The extractor implements a minimal subset of the PDF text extraction rules. It
understands a few common encodings:

* **StandardEncoding** – Adobe's base Latin encoding
* **WinAnsiEncoding** – Windows‑1252
* **MacRomanEncoding** and **MacExpertEncoding** – simplified mappings used by
  older Mac fonts
* **PDFDocEncoding** – the default encoding for strings in PDF files

Glyph names encountered in font dictionaries are converted to Unicode characters
using a small lookup table.  This is intentionally lightweight but sufficient to
recover standard Latin text from most simple PDFs.

### Running tests

Run the public tests with:

```bash
cargo test
```

Private tests can be run with:

```bash
cargo test --features private_tests
```
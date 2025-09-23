# PDF Verification WASM

A WebAssembly wrapper for PDF text extraction and digital signature verification. Provides browser-compatible JavaScript/TypeScript bindings for PDF verification in web applications.

## 🚀 **Quick Start**

```bash
# Build WASM module and copy into app/public/pkg directly
./generate_wasm.sh

```

## 📋 **API Functions**

| Function                                   | Description                            |
| ------------------------------------------ | -------------------------------------- |
| `extractText(pdfBytes)`                    | Extract text from all PDF pages        |
| `verifySignature(pdfBytes)`                | Verify PDF digital signature           |
| `verifyText(pdfBytes, page, text, offset)` | Combined text + signature verification |

## 📝 **Usage Example**

```javascript
import { verifyText, extractText } from "./pkg/wasm.js";

// Initialize WASM
await wasm.init();

// Extract text
const pages = extractText(pdfBytes);
console.log("Pages:", pages);

// Verify text at position
const result = verifyText(pdfBytes, 0, "Sample Text", 100);
console.log("Text found:", result.substring_matches);
console.log("Signature valid:", result.signature.is_valid);
```

## 🌐 **Browser Support**

- ✅ Chrome, Firefox, Safari, Edge

## 📚 **Dependencies**

- `wasm-bindgen` – Rust-WASM bindings
- `serde` – Serialization framework
- `base64` – Base64 encoding/decoding

## 📄 **License**

This crate is licensed under the same terms as the parent repository.

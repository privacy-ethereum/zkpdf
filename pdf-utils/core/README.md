# core

`core` provides a simple function that verifies a PDF's digital signature and checks for text at a specific position.

## Main Interface

```rust
pub fn verify_text(
    pdf_bytes: Vec<u8>,
    page_number: u8,
    sub_string: &str,
    position: usize,
) -> Result<bool, String>
```

The function returns `Ok(true)` when the signature is valid and `sub_string` appears at `position` on the indicated page.

### Running tests

Public tests:

```bash
cargo test -p core
```

Private tests:

```bash
cargo test -p core --features private_tests
```

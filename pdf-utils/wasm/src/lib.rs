use core::verify_text;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn wasm_verify_text(
    pdf_bytes: &[u8],
    page_number: u8,
    sub_string: &str,
    position: usize,
) -> bool {
    verify_text(pdf_bytes.to_vec(), page_number, sub_string, position).unwrap_or(false)
}

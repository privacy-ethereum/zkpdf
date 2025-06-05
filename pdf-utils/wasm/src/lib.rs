use core::verify_text;
use extractor::extract_text;
use wasm_bindgen::prelude::*;

/// WebAssembly export: verify text and signature in a PDF
#[wasm_bindgen]
pub fn wasm_verify_text(pdf_bytes: &[u8], page_number: u8, sub_string: &str) -> bool {
    verify_text(pdf_bytes.to_vec(), page_number, sub_string).unwrap_or(false)
}

/// WebAssembly export: extract raw text content per page
#[wasm_bindgen]
pub fn wasm_extract_text(pdf_bytes: &[u8]) -> Vec<JsValue> {
    match extract_text(pdf_bytes.to_vec()) {
        Ok(pages) => pages.into_iter().map(JsValue::from).collect(),
        Err(_) => Vec::new(),
    }
}

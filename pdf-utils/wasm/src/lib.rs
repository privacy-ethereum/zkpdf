use base64::{Engine as _, engine::general_purpose};
use core::{verify_and_extract, verify_pdf_signature, verify_text};
use extractor::extract_text;
use serde::Serialize;
use serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct SignatureInfo {
    is_valid: bool,
    message_digest: String,
    public_key: String,
}

#[derive(Serialize)]
struct VerifyAndExtractResult {
    success: bool,
    pages: Vec<String>,
    signature: SignatureInfo,
}

#[derive(Serialize)]
struct VerifySignatureResult {
    success: bool,
    is_valid: bool,
    message_digest: String,
    public_key: String,
}

#[derive(Serialize)]
struct VerifyTextResult {
    success: bool,
    substring_matches: bool,
    signature: SignatureInfo,
}

#[derive(Serialize)]
struct ErrorResult {
    success: bool,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    substring_matches: Option<bool>,
}

/// WebAssembly export: verify and extract content from PDF (signature verification + text extraction)
#[wasm_bindgen]
pub fn wasm_verify_and_extract(pdf_bytes: &[u8]) -> Result<JsValue, String> {
    match verify_and_extract(pdf_bytes.to_vec()) {
        Ok(content) => {
            let result = VerifyAndExtractResult {
                success: true,
                pages: content.pages,
                signature: SignatureInfo {
                    is_valid: content.signature.is_valid,
                    message_digest: general_purpose::STANDARD
                        .encode(&content.signature.message_digest),
                    public_key: general_purpose::STANDARD.encode(&content.signature.public_key),
                },
            };
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| format!("Failed to serialize result: {}", e))
        }
        Err(e) => {
            let error_result = ErrorResult {
                success: false,
                error: e,
                is_valid: None,
                substring_matches: None,
            };
            serde_wasm_bindgen::to_value(&error_result)
                .map_err(|e| format!("Failed to serialize error: {}", e))
        }
    }
}

/// WebAssembly export: verify text and signature in a PDF at a specific offset
/// Returns a JSON object with success status and error message (if any)
#[wasm_bindgen]
pub fn wasm_verify_text(
    pdf_bytes: &[u8],
    page_number: u8,
    sub_string: &str,
    offset: usize,
) -> Result<JsValue, String> {
    match verify_text(pdf_bytes.to_vec(), page_number, sub_string, offset) {
        Ok(result) => {
            let response = VerifyTextResult {
                success: true,
                substring_matches: result.substring_matches,
                signature: SignatureInfo {
                    is_valid: result.signature.is_valid,
                    message_digest: general_purpose::STANDARD
                        .encode(&result.signature.message_digest),
                    public_key: general_purpose::STANDARD.encode(&result.signature.public_key),
                },
            };
            serde_wasm_bindgen::to_value(&response)
                .map_err(|e| format!("Failed to serialize result: {}", e))
        }
        Err(e) => {
            let error_result = ErrorResult {
                success: false,
                error: e,
                is_valid: None,
                substring_matches: Some(false),
            };
            serde_wasm_bindgen::to_value(&error_result)
                .map_err(|e| format!("Failed to serialize error: {}", e))
        }
    }
}

/// WebAssembly export: verify PDF signature only (no text extraction)
/// Returns a JSON object with signature verification results
#[wasm_bindgen]
pub fn wasm_verify_pdf_signature(pdf_bytes: &[u8]) -> Result<JsValue, String> {
    match verify_pdf_signature(pdf_bytes) {
        Ok(signature_result) => {
            let response = VerifySignatureResult {
                success: true,
                is_valid: signature_result.is_valid,
                message_digest: general_purpose::STANDARD.encode(&signature_result.message_digest),
                public_key: general_purpose::STANDARD.encode(&signature_result.public_key),
            };
            serde_wasm_bindgen::to_value(&response)
                .map_err(|e| format!("Failed to serialize result: {}", e))
        }
        Err(e) => {
            let error_result = ErrorResult {
                success: false,
                error: format!("Signature verification failed: {}", e),
                is_valid: Some(false),
                substring_matches: None,
            };
            serde_wasm_bindgen::to_value(&error_result)
                .map_err(|e| format!("Failed to serialize error: {}", e))
        }
    }
}

/// WebAssembly export: extract raw text content per page
#[wasm_bindgen]
pub fn wasm_extract_text(pdf_bytes: &[u8]) -> Vec<JsValue> {
    match extract_text(pdf_bytes.to_vec()) {
        Ok(pages) => pages.into_iter().map(JsValue::from).collect(),
        Err(_) => Vec::new(),
    }
}

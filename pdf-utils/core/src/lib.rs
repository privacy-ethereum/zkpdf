pub use extractor::extract_text;
pub use signature_validator::verify_pdf_signature;

/// Verifies a PDF's digital signature and checks that `sub_string` appears at `offset` on
/// `page_number`. Returns `Ok(true)` when the substring matches at the given position,
/// `Ok(false)` when it does not, and an `Err` for signature or extraction failures.
pub fn verify_text(
    pdf_bytes: Vec<u8>,
    page_number: u8,
    sub_string: &str,
    offset: usize,
) -> Result<bool, String> {
    // Step 1: verify signature
    match verify_pdf_signature(&pdf_bytes) {
        Ok(true) => {}
        Ok(false) => return Err("signature verification failed".to_string()),
        Err(e) => return Err(format!("signature verification error: {}", e)),
    }

    // Step 2: extract text
    let pages = extract_text(pdf_bytes).map_err(|e| format!("text extraction error: {:?}", e))?;
    let index = page_number as usize;
    if index >= pages.len() {
        return Err(format!(
            "page {} out of bounds (total pages: {})",
            page_number,
            pages.len()
        ));
    }

    // Step 3: check if substring matches exactly at the requested offset
    let page_text = &pages[index];
    Ok(page_text
        .get(offset..)
        .map(|slice| slice.starts_with(sub_string))
        .unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use extractor::extract_text;

    #[test]
    fn test_verify_text_public() {
        let pdf_bytes = include_bytes!("../../sample-pdfs/digitally_signed.pdf").to_vec();

        let name = "Sample Signed PDF Document";
        let page_number = 0;
        let pages = extract_text(pdf_bytes.clone()).expect("text extraction failed");
        let page_text = &pages[page_number as usize];
        let offset = page_text
            .find(name)
            .expect("expected substring missing from extracted text");
        let result = verify_text(pdf_bytes, page_number, name, offset);

        assert!(result.is_ok(), "Verification call failed: {:?}", result);
        assert!(result.unwrap(), "Text match failed at given offset");
    }
}

#[cfg(feature = "private_tests")]
mod core_test {
    use super::*;

    #[test]
    fn test_extract_text_and_verify() {
        let pdf_bytes = include_bytes!("../../samples-private/pan-cert.pdf").to_vec();

        let text = extract_text(pdf_bytes.clone()).expect("Text extraction failed");

        let page_number = 0;
        let name = "Digitally signed on\n22/11/2024";
        let page_text = &text[page_number as usize];
        let offset = page_text
            .find(name)
            .expect("expected substring missing from extracted text");
        let result = verify_text(pdf_bytes, page_number, name, offset);

        assert!(result.is_ok(), "Verification failed: {:?}", result);
        assert!(result.unwrap(), "Text match failed at given offset");
    }
}

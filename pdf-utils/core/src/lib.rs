use extractor::extract_text;
use signature_validator::verify_pdf_signature;

/// Verifies PDF signature and checks that `sub_string` appears at a specific `position`
/// in the given `page_number`. Returns a detailed error if any step fails.
/// Verifies PDF signature and checks that `sub_string` appears anywhere
/// in the given `page_number`. Returns a detailed error if any step fails.
pub fn verify_text(pdf_bytes: Vec<u8>, page_number: u8, sub_string: &str) -> Result<bool, String> {
    // Step 1: verify signature
    let is_valid = verify_pdf_signature(&pdf_bytes)
        .map_err(|e| format!("signature verification error: {}", e))?;
    if !is_valid {
        return Ok(false);
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

    // Step 3: check if substring is contained anywhere in the page
    let page_text = &pages[index];
    Ok(page_text.contains(sub_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_text_public() {
        let pdf_bytes = include_bytes!("../../sample-pdfs/digitally_signed.pdf").to_vec();

        let name = "Sample Signed PDF Document";
        let page_number = 0;
        let result = verify_text(pdf_bytes, page_number, name);

        assert!(result.is_ok(), "Verification call failed: {:?}", result);
        assert!(result.unwrap(), "Text match failed at given offset");
    }
}

#[cfg(feature = "private_tests")]
mod core_test {
    use super::*;
    use extractor::extract_text;

    #[test]
    fn test_extract_text_and_verify() {
        let pdf_bytes = include_bytes!("../../samples-private/pan-cert.pdf").to_vec();

        let text = extract_text(pdf_bytes.clone()).expect("Text extraction failed");

        let name = "Digitally signed on\n22/11/2024";
        let result = verify_text(pdf_bytes, page_number, name);

        assert!(result.is_ok(), "Verification failed: {:?}", result);
        assert!(result.unwrap(), "Text match failed at given offset");
    }
}

use extractor::extract_text;
use signature_validator::verify_pdf_signature;

/// Verifies PDF signature and checks that `sub_string` appears at a specific `position`
/// in the given `page_number`. Returns a detailed error if any step fails.
pub fn verify_text(
    pdf_bytes: Vec<u8>,
    page_number: u8,
    sub_string: &str,
    position: usize,
) -> Result<bool, String> {
    // verify signature
    let is_valid = verify_pdf_signature(&pdf_bytes)?;
    if !is_valid {
        return Ok(false);
    }

    // extract text
    let pages = extract_text(pdf_bytes).map_err(|e| format!("text extraction error: {:?}", e))?;

    // page length check
    let index = page_number as usize;
    if index >= pages.len() {
        return Err(format!(
            "page {} out of bounds (total: {})",
            page_number,
            pages.len()
        ));
    }

    // substring check
    let page_text = &pages[index];
    let slice = page_text.as_bytes();
    let sub_bytes = sub_string.as_bytes();

    // Out-of-range match
    if position + sub_bytes.len() > slice.len() {
        return Ok(false);
    }

    for (i, &b) in sub_bytes.iter().enumerate() {
        if slice[position + i] != b {
            return Ok(false); // Mismatch
        }
    }

    Ok(true)
}

#[cfg(test)]
mod test {
    use crate::verify_text;

    #[test]
    fn test_extract_text() {
        let pdf_bytes = include_bytes!("../../samples-private/bank-cert.pdf").to_vec();

        let name = "YELAGANDULA VIKAS RUSHI";
        let page_number = 0; // 0-indexed → Page 1
        let offset = 119;
        let result = verify_text(pdf_bytes, page_number, name, offset);

        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }
}

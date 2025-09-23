pub use extractor::extract_text;
pub use signature_validator::{types::PdfSignatureResult, verify_pdf_signature};

/// Result returned by `verify_text`, providing both the substring match and signature metadata.
pub struct PdfVerificationResult {
    pub substring_matches: bool,
    pub signature: PdfSignatureResult,
}

/// Verifies a PDF's digital signature and checks that `sub_string` appears at `offset` on
/// `page_number`. Returns signature metadata and a substring match flag on success, or an error for
/// signature/extraction failures.
pub fn verify_text(
    pdf_bytes: Vec<u8>,
    page_number: u8,
    sub_string: &str,
    offset: usize,
) -> Result<PdfVerificationResult, String> {
    // Step 1: verify signature and extract text
    let PdfVerifiedContent { pages, signature } = verify_and_extract(pdf_bytes)?;

    let index = page_number as usize;
    if index >= pages.len() {
        return Err(format!(
            "page {} out of bounds (total pages: {})",
            page_number,
            pages.len()
        ));
    }

    // Step 2: check if substring matches exactly at the requested offset
    let page_text = &pages[index];
    let result = page_text
        .get(offset..)
        .map(|slice| slice.starts_with(sub_string))
        .unwrap_or(false);

    Ok(PdfVerificationResult {
        substring_matches: result,
        signature,
    })
}

#[derive(Debug, Clone)]
pub struct PdfVerifiedContent {
    pub pages: Vec<String>,
    pub signature: PdfSignatureResult,
}

pub fn verify_and_extract(pdf_bytes: Vec<u8>) -> Result<PdfVerifiedContent, String> {
    // Step 1: verify signature
    let signature = verify_pdf_signature(&pdf_bytes)
        .map_err(|e| format!("signature verification error: {}", e))?;
    if !signature.is_valid {
        return Err("signature verification failed".to_string());
    }

    // Step 2: extract text
    let pages = extract_text(pdf_bytes).map_err(|e| format!("text extraction error: {:?}", e))?;

    Ok(PdfVerifiedContent { pages, signature })
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
        let result = verify_text(pdf_bytes, page_number, name, offset).unwrap();

        assert!(result.signature.is_valid, "Signature verification failed");
        assert!(
            result.substring_matches,
            "Text match failed at given offset"
        );
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
        let result = verify_text(pdf_bytes, page_number, name, offset).unwrap();

        assert!(result.signature.is_valid, "Signature verification failed");
        assert!(
            result.substring_matches,
            "Text match failed at given offset"
        );
    }
}

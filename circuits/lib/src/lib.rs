pub mod nullifier;
pub mod types;

pub use extractor::extract_text;
pub use pdf_core::verify_text;
pub use signature_validator::verify_pdf_signature;
pub use types::PublicValuesStruct;

use crate::types::{PDFCircuitInput, PDFCircuitOutput};

pub fn verify_pdf_claim(input: PDFCircuitInput) -> Result<PDFCircuitOutput, String> {
    let PDFCircuitInput {
        pdf_bytes,
        page_number,
        offset,
        substring,
    } = input;

    // Step 1: verify signature and offset from verify_text function
    let result = verify_text(pdf_bytes, page_number, substring.as_str(), offset as usize)?;

    // Step 2: construct output
    Ok(PDFCircuitOutput::from_verification(
        &substring,
        page_number,
        offset,
        result,
    ))
}

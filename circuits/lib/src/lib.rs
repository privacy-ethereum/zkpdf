// Public modules
pub mod gst_example; // GST certificate verification logic
pub mod nullifier; // Nullifier utilities for ZK circuits
pub mod types; // Shared data structures

// Re-exports for main API surface
pub use extractor::extract_text; // PDF text extraction
pub use gst_example::verify_gst_certificate; // GST certificate check
pub use pdf_core::{
    verify_and_extract, // Verify + extract in one call
    verify_text,        // Verify substring at offset
    PdfSignatureResult,
    PdfVerificationResult,
    PdfVerifiedContent,
};
pub use signature_validator::verify_pdf_signature; // Signature-only verification
pub use types::PublicValuesStruct; // Public circuit values

// Internal circuit types (not re-exported)
use crate::types::{PDFCircuitInput, PDFCircuitOutput};

/// Generic PDF verification function for basic text extraction and signature verification
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

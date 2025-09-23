use pdf_core::PdfSignatureResult;

pub struct GSTCertificate {
    pub gst_number: String,
    pub legal_name: String,
    pub signature: PdfSignatureResult,
}
/// GST Certificate verification function that extracts legal name and GST number
pub fn verify_gst_certificate(pdf_bytes: Vec<u8>) -> GSTCertificate {
    let verified_content = pdf_core::verify_and_extract(pdf_bytes).unwrap();

    let full_text = verified_content.pages.join(" ");

    let gst_pattern =
        regex::Regex::new(r"([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}[Z]{1}[0-9A-Z]{1})")
            .unwrap();

    let gst_number = gst_pattern
        .captures(&full_text)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap();

    let legal_name_pattern =
        regex::Regex::new(r"Legal Name\s*([A-Za-z\s&.,]+?)(?:\n|Trade Name|Additional|$)").unwrap();

    let legal_name = legal_name_pattern
        .captures(&full_text)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap();

    GSTCertificate {
        gst_number,
        legal_name,
        signature: verified_content.signature,
    }
}

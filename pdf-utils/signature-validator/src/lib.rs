pub mod pkcs7_parser;
pub mod signed_bytes_extractor;
pub mod types;

use pkcs7_parser::{parse_signed_data, VerifierParams};
use rsa::{errors::Error as RsaError, pkcs1::EncodeRsaPublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signed_bytes_extractor::get_signature_der;
use types::{SignatureAlgorithm, SignatureResult, SignatureValidationError};

use crate::types::PdfSignatureResult;

fn calculate_signed_data_hash(
    signed_data: &[u8],
    algorithm: &SignatureAlgorithm,
) -> SignatureResult<Vec<u8>> {
    match algorithm {
        SignatureAlgorithm::Sha1WithRsaEncryption => {
            let mut hasher = Sha1::new();
            hasher.update(signed_data);
            Ok(hasher.finalize().to_vec())
        }
        SignatureAlgorithm::Sha256WithRsaEncryption => {
            let mut hasher = Sha256::new();
            hasher.update(signed_data);
            Ok(hasher.finalize().to_vec())
        }
        SignatureAlgorithm::Sha384WithRsaEncryption => {
            let mut hasher = Sha384::new();
            hasher.update(signed_data);
            Ok(hasher.finalize().to_vec())
        }
        SignatureAlgorithm::Sha512WithRsaEncryption => {
            let mut hasher = Sha512::new();
            hasher.update(signed_data);
            Ok(hasher.finalize().to_vec())
        }
        other => Err(SignatureValidationError::UnsupportedAlgorithm(
            other.clone(),
        )),
    }
}

fn create_rsa_public_key(verifier_params: &VerifierParams) -> SignatureResult<RsaPublicKey> {
    RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&verifier_params.modulus),
        rsa::BigUint::from_bytes_be(&verifier_params.exponent.to_bytes_be()),
    )
    .map_err(|e| SignatureValidationError::InvalidPublicKey(e.to_string()))
}

fn get_pkcs1v15_padding(algorithm: &SignatureAlgorithm) -> SignatureResult<Pkcs1v15Sign> {
    match algorithm {
        SignatureAlgorithm::Sha1WithRsaEncryption => Ok(Pkcs1v15Sign::new::<Sha1>()),
        SignatureAlgorithm::Sha256WithRsaEncryption => Ok(Pkcs1v15Sign::new::<Sha256>()),
        SignatureAlgorithm::Sha384WithRsaEncryption => Ok(Pkcs1v15Sign::new::<Sha384>()),
        SignatureAlgorithm::Sha512WithRsaEncryption => Ok(Pkcs1v15Sign::new::<Sha512>()),
        other => Err(SignatureValidationError::UnsupportedAlgorithm(
            other.clone(),
        )),
    }
}

fn verify_rsa_signature(
    pub_key: &RsaPublicKey,
    padding: Pkcs1v15Sign,
    signed_attr_digest: &[u8],
    signature: &[u8],
) -> SignatureResult<bool> {
    match pub_key.verify(padding, signed_attr_digest, signature) {
        Ok(_) => Ok(true),
        Err(RsaError::Verification) => Ok(false),
        Err(e) => Err(SignatureValidationError::SignatureVerification(
            e.to_string(),
        )),
    }
}

pub fn verify_pdf_signature(pdf_bytes: &[u8]) -> SignatureResult<PdfSignatureResult> {
    let (signature_der, signed_data) = get_signature_der(pdf_bytes)?;

    let verifier_params = parse_signed_data(&signature_der)?;

    // CHECK 1: Verify message digest
    let calculated_signed_data_hash =
        calculate_signed_data_hash(&signed_data, &verifier_params.algorithm)?;

    if let Some(expected) = &verifier_params.signed_data_message_digest {
        if expected != &calculated_signed_data_hash {
            return Err(SignatureValidationError::MessageDigestMismatch {
                expected: expected.clone(),
                calculated: calculated_signed_data_hash,
            });
        }
    }

    // CHECK 2: Verify RSA signature
    let pub_key = create_rsa_public_key(&verifier_params)?;
    let padding = get_pkcs1v15_padding(&verifier_params.algorithm)?;
    let digest_for_signature = verifier_params
        .signed_attr_digest
        .clone()
        .unwrap_or_else(|| calculated_signed_data_hash.clone());
    let is_verified = verify_rsa_signature(
        &pub_key,
        padding,
        &digest_for_signature,
        &verifier_params.signature,
    )?;

    Ok(PdfSignatureResult {
        is_valid: is_verified,
        message_digest: verifier_params
            .signed_data_message_digest
            .clone()
            .unwrap_or(calculated_signed_data_hash),
        public_key: pub_key
            .to_pkcs1_der()
            .expect("Failed to encode public key")
            .as_bytes()
            .to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // PUBLIC PDF
    static SAMPLE_PDF_BYTES: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed.pdf");
    #[test]
    fn test_sha1_pdf() {
        let res = verify_pdf_signature(SAMPLE_PDF_BYTES);
        assert!(matches!(res, Ok(PdfSignatureResult { is_valid: true, .. })));
    }

    #[test]
    fn test_gst_template_pdf() {
        let pdf_bytes: &[u8] = include_bytes!("../../sample-pdfs/GST-certificate.pdf");
        let res = verify_pdf_signature(&pdf_bytes)
            .expect("GST certificate signature verification failed");

        assert!(res.is_valid, "GST certificate signature reported invalid");
    }

    #[cfg(feature = "private_tests")]
    mod private {
        use super::*;

        // digilocker pdfs
        // 1. bank-cert.pdf: Signed with SHA256withRSA
        // 2. pan-cert.pdf: Signed with SHA256withRSA
        // 4. tenth_class.pdf signed with SHA1withRSA

        #[test]
        fn sig_check_bank_pdf() {
            let pdf_bytes: &[u8] = include_bytes!("../../samples-private/bank-cert.pdf");
            let res = verify_pdf_signature(&pdf_bytes);
            assert!(matches!(res, Ok(PdfSignatureResult { is_valid: true, .. })));
        }

        #[test]
        fn sign_check_pan_pdf() {
            let pdf_bytes: &[u8] = include_bytes!("../../samples-private/pan-cert.pdf");
            let res = verify_pdf_signature(&pdf_bytes);
            assert!(matches!(res, Ok(PdfSignatureResult { is_valid: true, .. })));
        }

        #[test]
        fn sig_check_tenth_class_pdf() {
            let pdf_bytes: &[u8] = include_bytes!("../../samples-private/tenth_class.pdf");
            let res = verify_pdf_signature(&pdf_bytes);
            assert!(matches!(res, Ok(PdfSignatureResult { is_valid: true, .. })));
        }
    }
}

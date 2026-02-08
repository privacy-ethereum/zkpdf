pub mod ber;
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

/// Build a PKCS#1 v1.5 DigestInfo prefix that omits the NULL parameter after the hash algorithm OID
fn get_pkcs1v15_padding_no_null(algorithm: &SignatureAlgorithm) -> SignatureResult<Pkcs1v15Sign> {
    let (oid, hash_len): (&[u8], usize) = match algorithm {
        SignatureAlgorithm::Sha1WithRsaEncryption => (
            &[0x2B, 0x0E, 0x03, 0x02, 0x1A], // 1.3.14.3.2.26
            20,
        ),
        SignatureAlgorithm::Sha256WithRsaEncryption => (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01], // 2.16.840.1.101.3.4.2.1
            32,
        ),
        SignatureAlgorithm::Sha384WithRsaEncryption => (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02], // 2.16.840.1.101.3.4.2.2
            48,
        ),
        SignatureAlgorithm::Sha512WithRsaEncryption => (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03], // 2.16.840.1.101.3.4.2.3
            64,
        ),
        other => {
            return Err(SignatureValidationError::UnsupportedAlgorithm(
                other.clone(),
            ))
        }
    };
    let oid_len = oid.len() as u8;
    let digest_len = hash_len as u8;
    // No NULL, AlgorithmIdentifier is 2 bytes shorter
    let mut prefix = vec![
        0x30,
        oid_len + 6 + digest_len, // outer SEQUENCE length
        0x30,
        oid_len + 2, // AlgorithmIdentifier length (no 05 00)
        0x06,
        oid_len,
    ];
    prefix.extend_from_slice(oid);
    // No 05 00 here
    prefix.extend_from_slice(&[0x04, digest_len]);

    Ok(Pkcs1v15Sign {
        hash_len: Some(hash_len),
        prefix: prefix.into_boxed_slice(),
    })
}

fn verify_rsa_signature(
    pub_key: &RsaPublicKey,
    padding: Pkcs1v15Sign,
    signed_attr_digest: &[u8],
    signature: &[u8],
    algorithm: &SignatureAlgorithm,
) -> SignatureResult<bool> {
    match pub_key.verify(padding, signed_attr_digest, signature) {
        Ok(_) => Ok(true),
        Err(RsaError::Verification) => {
            // Retry with no-NULL DigestInfo prefix (RFC4055 variant)
            let alt_padding = get_pkcs1v15_padding_no_null(algorithm)?;
            match pub_key.verify(alt_padding, signed_attr_digest, signature) {
                Ok(_) => Ok(true),
                Err(RsaError::Verification) => Ok(false),
                Err(e) => Err(SignatureValidationError::SignatureVerification(
                    e.to_string(),
                )),
            }
        }
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
        &verifier_params.algorithm,
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

    #[test]
    fn test_pades_cades_detached() {
        // PAdES signature with SubFilter ETSI.CAdES.detached
        // Uses BER indefinite-length encoding (0x80) in the CMS structure
        // and DigestInfo without NULL parameter (RFC 4055 variant)
        let pdf_bytes: &[u8] = include_bytes!("../../sample-pdfs/pades_signed.pdf");

        let res = verify_pdf_signature(pdf_bytes)
            .expect("PAdES CAdES.detached signature verification failed");
        assert!(res.is_valid, "PAdES signature reported invalid");
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

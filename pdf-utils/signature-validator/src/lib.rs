pub mod pkcs7_parser;
pub mod signed_bytes_extractor;

use pkcs7_parser::{parse_signed_data, VerifierParams};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signed_bytes_extractor::get_signature_der;
use simple_asn1::OID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Sha1WithRsaEncryption,
    Sha256WithRsaEncryption,
    Sha384WithRsaEncryption,
    Sha512WithRsaEncryption,
    RsaEncryption,
    RsaEncryptionWithUnknownHash(OID),
    Unknown(OID),
}

fn calculate_signed_data_hash(
    signed_data: &[u8],
    algorithm: &SignatureAlgorithm,
) -> Result<Vec<u8>, String> {
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
        _ => Err("Unsupported signature algorithm for hash calculation".to_string()),
    }
}

fn create_rsa_public_key(verifier_params: &VerifierParams) -> Result<RsaPublicKey, String> {
    RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&verifier_params.modulus),
        rsa::BigUint::from_bytes_be(&verifier_params.exponent.to_bytes_be()),
    )
    .map_err(|e| e.to_string())
}

fn get_pkcs1v15_padding(algorithm: &SignatureAlgorithm) -> Result<Pkcs1v15Sign, String> {
    match algorithm {
        SignatureAlgorithm::Sha1WithRsaEncryption => Ok(Pkcs1v15Sign::new::<Sha1>()),
        SignatureAlgorithm::Sha256WithRsaEncryption => Ok(Pkcs1v15Sign::new::<Sha256>()),
        SignatureAlgorithm::Sha384WithRsaEncryption => Ok(Pkcs1v15Sign::new::<Sha384>()),
        SignatureAlgorithm::Sha512WithRsaEncryption => Ok(Pkcs1v15Sign::new::<Sha512>()),
        SignatureAlgorithm::RsaEncryption => {
            Err("Raw RSA encryption padding not supported".to_string())
        }
        SignatureAlgorithm::RsaEncryptionWithUnknownHash(_) => {
            Err("RSA with unknown hash padding not supported".to_string())
        }
        SignatureAlgorithm::Unknown(_) => Err("Unknown padding type".to_string()),
    }
}

fn verify_rsa_signature(
    pub_key: &RsaPublicKey,
    padding: Pkcs1v15Sign,
    signed_attr_digest: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    pub_key
        .verify(padding, signed_attr_digest, signature)
        .map(|_| true)
        .map_err(|e| e.to_string())
}

pub fn verify_pdf_signature(pdf_bytes: &[u8]) -> Result<bool, String> {
    let (signature_der, signed_data) =
        get_signature_der(pdf_bytes).map_err(|_| "Failed to extract signed data".to_string())?;

    let verifier_params = parse_signed_data(&signature_der)
        .map_err(|e| format!("Failed to parse signed data: {}", e))?;

    // CHECK 1: Verify message digest
    let calculated_signed_data_hash =
        calculate_signed_data_hash(&signed_data, &verifier_params.algorithm)?;

    if verifier_params.signed_data_message_digest != calculated_signed_data_hash {
        return Err("Message digest mismatch".to_string());
    }

    // CHECK 2: Verify RSA signature
    let pub_key = create_rsa_public_key(&verifier_params)?;
    let padding = get_pkcs1v15_padding(&verifier_params.algorithm)?;
    let is_verified = verify_rsa_signature(
        &pub_key,
        padding,
        &verifier_params.signed_attr_digest,
        &verifier_params.signature,
    )?;

    Ok(is_verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    // PUBLIC PDF
    static SAMPLE_PDF_BYTES: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed.pdf");

    #[test]
    fn test_sha1_pdf() {
        let res = verify_pdf_signature(SAMPLE_PDF_BYTES);
        assert!(res.is_ok());
    }

    #[cfg(feature = "private_tests")]
    mod private {
        use super::*;
        use std::fs;
        use std::path::Path;

        #[test]
        fn test_sha256_pdf_private() {
            let private_file_path = Path::new("../../samples-private/bank-cert.pdf");
            if private_file_path.exists() {
                let pdf_bytes = fs::read(private_file_path).expect("Failed to read private PDF");
                let res = verify_pdf_signature(&pdf_bytes);
                assert!(res.is_ok());
            } else {
                eprintln!(
                    "Skipping private test: '../../samples-private/bank-cert.pdf' not found."
                );
            }
        }

        #[test]
        fn test_sha1_with_rsa_encryption_private() {
            let private_file_path = Path::new("../../samples-private/pan-cert.pdf");
            if private_file_path.exists() {
                let pdf_bytes = fs::read(private_file_path).expect("Failed to read private PDF");
                let res = verify_pdf_signature(&pdf_bytes);
                assert!(res.is_ok());
            } else {
                eprintln!("Skipping private test: '../../samples-private/pan-cert.pdf' not found.");
            }
        }
    }
}

pub mod ber;
pub mod pkcs7_parser;
pub mod signed_bytes_extractor;
pub mod types;

use p256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature,
    VerifyingKey as P384VerifyingKey,
};
use pkcs7_parser::parse_signed_data;
use rsa::{errors::Error as RsaError, pkcs1::EncodeRsaPublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signed_bytes_extractor::get_signature_der;
use simple_asn1::oid;
use types::{
    PdfSignatureResult, PublicKeyType, SignatureAlgorithm, SignatureResult,
    SignatureValidationError,
};

// NOTE on algorithm routing:
//
// In a CMS/PKCS#7 SignedData structure the `digestAlgorithm` field in SignerInfo always
// carries a bare hash OID (e.g. id-sha256 = 2.16.840.1.101.3.4.2.1), regardless of
// whether the signer used RSA or ECDSA.  The combined "ecdsa-with-SHA256" OID
// (1.2.840.10045.4.3.2) only ever appears in a certificate's signatureAlgorithm field,
// not in the digestAlgorithm field we parse here.
//
// Consequence: `digest_algorithm_from_oid` will always return an Sha*WithRsaEncryption
// variant for real PDFs, even ECDSA-signed ones.  The EcdsaWithSha* variants in
// `SignatureAlgorithm` are therefore dead code for the PDF path; they exist for
// forward-compatibility and unit-test symmetry.
//
// Signature routing is intentionally done on `PublicKeyType` (from the certificate),
// not on the `SignatureAlgorithm` label.  This is correct: the label tells us *which
// hash* to use, the key type tells us *which signature scheme* to run.
//
// NOTE on prehash vs message verification:
//
// The p256/p384 `Verifier` trait (verify()) takes a raw *message* and hashes it
// internally before checking the ECDSA signature.  Real-world signers (pyHanko,
// Adobe, OpenSSL high-level API) compute SHA256(signedAttrs) and sign *that* hash
// directly — they do not double-hash.
//
// Calling verify(digest, sig) would therefore compute SHA256(SHA256(signedAttrs))
// internally, which never matches.
//
// The fix is `verify_prehash(digest, sig)` which passes the hash bytes straight to
// the ECDSA verification primitive without any additional hashing.

fn calculate_signed_data_hash(
    signed_data: &[u8],
    algorithm: &SignatureAlgorithm,
) -> SignatureResult<Vec<u8>> {
    match algorithm {
        SignatureAlgorithm::Sha1WithRsaEncryption | SignatureAlgorithm::EcdsaWithSha1 => {
            let mut hasher = Sha1::new();
            hasher.update(signed_data);
            Ok(hasher.finalize().to_vec())
        }
        SignatureAlgorithm::Sha256WithRsaEncryption | SignatureAlgorithm::EcdsaWithSha256 => {
            let mut hasher = Sha256::new();
            hasher.update(signed_data);
            Ok(hasher.finalize().to_vec())
        }
        SignatureAlgorithm::Sha384WithRsaEncryption | SignatureAlgorithm::EcdsaWithSha384 => {
            let mut hasher = Sha384::new();
            hasher.update(signed_data);
            Ok(hasher.finalize().to_vec())
        }
        SignatureAlgorithm::Sha512WithRsaEncryption | SignatureAlgorithm::EcdsaWithSha512 => {
            let mut hasher = Sha512::new();
            hasher.update(signed_data);
            Ok(hasher.finalize().to_vec())
        }
        other => Err(SignatureValidationError::UnsupportedAlgorithm(
            other.clone(),
        )),
    }
}

fn create_rsa_public_key(
    modulus: &[u8],
    exponent: &num_bigint::BigUint,
) -> SignatureResult<RsaPublicKey> {
    RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(&exponent.to_bytes_be()),
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

fn verify_ecdsa_signature(
    curve_oid: &simple_asn1::OID,
    public_key_point: &[u8],
    digest: &[u8],
    signature_bytes: &[u8],
) -> SignatureResult<bool> {
    if *curve_oid == oid!(1, 2, 840, 10045, 3, 1, 7) {
        // P-256 (secp256r1 / prime256v1)
        verify_p256_signature(public_key_point, digest, signature_bytes)
    } else if *curve_oid == oid!(1, 3, 132, 0, 34) {
        // P-384 (secp384r1)
        verify_p384_signature(public_key_point, digest, signature_bytes)
    } else {
        Err(SignatureValidationError::EcdsaVerification(format!(
            "Unsupported curve OID: {:?}",
            curve_oid
        )))
    }
}

/// Verify a DER-encoded ECDSA-P256 signature against a pre-hashed digest.

/// Uses `verify_prehash` so the digest bytes are passed directly to the ECDSA
/// verification primitive WITHOUT any additional internal hashing.
/// Real-world signers (pyHanko, Adobe, OpenSSL) produce signatures over the
/// hash, not over the raw message — passing the hash to `verify()` would
/// double-hash and always fail.
fn verify_p256_signature(
    public_key_point: &[u8],
    digest: &[u8],
    signature_bytes: &[u8],
) -> SignatureResult<bool> {
    let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_point)
        .map_err(|e| SignatureValidationError::InvalidEcdsaPublicKey(e.to_string()))?;
    let signature = P256Signature::from_der(signature_bytes)
        .map_err(|e| SignatureValidationError::EcdsaVerification(e.to_string()))?;
    match verifying_key.verify_prehash(digest, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}


fn verify_p384_signature(
    public_key_point: &[u8],
    digest: &[u8],
    signature_bytes: &[u8],
) -> SignatureResult<bool> {
    let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key_point)
        .map_err(|e| SignatureValidationError::InvalidEcdsaPublicKey(e.to_string()))?;
    let signature = P384Signature::from_der(signature_bytes)
        .map_err(|e| SignatureValidationError::EcdsaVerification(e.to_string()))?;
    match verifying_key.verify_prehash(digest, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn encode_public_key_to_der(public_key: &PublicKeyType) -> SignatureResult<Vec<u8>> {
    match public_key {
        PublicKeyType::Rsa { modulus, exponent } => {
            let pub_key = create_rsa_public_key(modulus, exponent)?;
            Ok(pub_key
                .to_pkcs1_der()
                .map_err(|e| SignatureValidationError::InvalidPublicKey(e.to_string()))?
                .as_bytes()
                .to_vec())
        }
        PublicKeyType::Ecdsa {
            curve_oid,
            public_key_point,
        } => {
            if *curve_oid == oid!(1, 2, 840, 10045, 3, 1, 7) {
                let vk = P256VerifyingKey::from_sec1_bytes(public_key_point)
                    .map_err(|e| SignatureValidationError::InvalidEcdsaPublicKey(e.to_string()))?;
                Ok(vk.to_encoded_point(false).as_bytes().to_vec())
            } else if *curve_oid == oid!(1, 3, 132, 0, 34) {
                let vk = P384VerifyingKey::from_sec1_bytes(public_key_point)
                    .map_err(|e| SignatureValidationError::InvalidEcdsaPublicKey(e.to_string()))?;
                Ok(vk.to_encoded_point(false).as_bytes().to_vec())
            } else {
                Err(SignatureValidationError::EcdsaVerification(format!(
                    "Unsupported curve for public key encoding: {:?}",
                    curve_oid
                )))
            }
        }
    }
}

pub fn verify_pdf_signature(pdf_bytes: &[u8]) -> SignatureResult<PdfSignatureResult> {
    let (signature_der, signed_data) = get_signature_der(pdf_bytes)?;
    let verifier_params = parse_signed_data(&signature_der)?;

    // CHECK 1 — content integrity: hash the signed byte ranges and compare with
    // the messageDigest attribute embedded in the SignedData.
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

    // CHECK 2 — signature authenticity: verify the cryptographic signature over
    // the signed attributes using the public key from the signer's certificate.
    // Routing is on key type, not on the SignatureAlgorithm label
    let digest_for_signature = verifier_params
        .signed_attr_digest
        .clone()
        .unwrap_or_else(|| calculated_signed_data_hash.clone());

    let is_verified = match &verifier_params.public_key {
        PublicKeyType::Rsa { modulus, exponent } => {
            let pub_key = create_rsa_public_key(modulus, exponent)?;
            let padding = get_pkcs1v15_padding(&verifier_params.algorithm)?;
            verify_rsa_signature(
                &pub_key,
                padding,
                &digest_for_signature,
                &verifier_params.signature,
                &verifier_params.algorithm,
            )?
        }
        PublicKeyType::Ecdsa {
            curve_oid,
            public_key_point,
        } => verify_ecdsa_signature(
            curve_oid,
            public_key_point,
            &digest_for_signature,
            &verifier_params.signature,
        )?,
    };

    let public_key_der = encode_public_key_to_der(&verifier_params.public_key)?;

    Ok(PdfSignatureResult {
        is_valid: is_verified,
        message_digest: verifier_params
            .signed_data_message_digest
            .clone()
            .unwrap_or(calculated_signed_data_hash),
        public_key: public_key_der,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

#[cfg(test)]
mod ecdsa_tests {
    use super::*;
    use rand_core::OsRng;

    // P-256 unit tests
    // These use sign_prehash / verify_prehash so both sides agree on semantics:
    // the "digest" bytes are passed straight to the ECDSA primitive, no re-hashing.

    #[test]
    fn test_ecdsa_p256_valid_signature() {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let digest = Sha256::digest(b"Test message for ECDSA P-256");

        // sign_prehash: sign the raw digest WITHOUT internal re-hashing
        let sig: P256Signature = signing_key.sign_prehash(&digest).unwrap();
        let point = verifying_key.to_encoded_point(false);

        let result = verify_p256_signature(point.as_bytes(), &digest, sig.to_der().as_bytes());
        assert!(result.is_ok());
        assert!(result.unwrap(), "valid P-256 signature should verify");
    }

    #[test]
    fn test_ecdsa_p256_wrong_key_rejected() {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let signing_key = SigningKey::random(&mut OsRng);
        let wrong_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let digest = Sha256::digest(b"Test message");
        let sig: P256Signature = wrong_key.sign_prehash(&digest).unwrap();
        let point = verifying_key.to_encoded_point(false);

        let result = verify_p256_signature(point.as_bytes(), &digest, sig.to_der().as_bytes());
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "signature from wrong key must be rejected"
        );
    }

    #[test]
    fn test_ecdsa_p256_tampered_digest_rejected() {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let original_digest = Sha256::digest(b"Original message");
        let tampered_digest = Sha256::digest(b"Tampered message");

        let sig: P256Signature = signing_key.sign_prehash(&original_digest).unwrap();
        let point = verifying_key.to_encoded_point(false);

        let result =
            verify_p256_signature(point.as_bytes(), &tampered_digest, sig.to_der().as_bytes());
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "signature over original must not verify against tampered digest"
        );
    }

    // P-384 unit tests

    #[test]
    fn test_ecdsa_p384_valid_signature() {
        use p384::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let digest = Sha384::digest(b"Test message for ECDSA P-384");
        let sig: P384Signature = signing_key.sign_prehash(&digest).unwrap();
        let point = verifying_key.to_encoded_point(false);

        let result = verify_p384_signature(point.as_bytes(), &digest, sig.to_der().as_bytes());
        assert!(result.is_ok());
        assert!(result.unwrap(), "valid P-384 signature should verify");
    }

    #[test]
    fn test_ecdsa_p384_wrong_key_rejected() {
        use p384::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let signing_key = SigningKey::random(&mut OsRng);
        let wrong_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let digest = Sha384::digest(b"Test message");
        let sig: P384Signature = wrong_key.sign_prehash(&digest).unwrap();
        let point = verifying_key.to_encoded_point(false);

        let result = verify_p384_signature(point.as_bytes(), &digest, sig.to_der().as_bytes());
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "signature from wrong key must be rejected"
        );
    }

    //  Curve dispatch 

    #[test]
    fn test_unsupported_curve_returns_error() {
        let unknown_curve = oid!(1, 2, 3, 4, 5);
        let result = verify_ecdsa_signature(&unknown_curve, &[0x04, 0x00], &[], &[]);
        assert!(
            matches!(result, Err(SignatureValidationError::EcdsaVerification(_))),
            "unsupported curve OID must return EcdsaVerification error"
        );
    }

    // Real pyHanko-signed PDF

    static ECDSA_P256_PDF: &[u8] = include_bytes!("../../sample-pdfs/ecdsa256_signed.pdf");

    #[test]
    fn test_ecdsa_p256_pdf_is_valid() {
        let result =
            verify_pdf_signature(ECDSA_P256_PDF).expect("P-256 PDF: verification should not error");
        assert!(result.is_valid, "P-256 PDF: signature should be valid");
    }

    #[test]
    fn test_ecdsa_p256_pdf_public_key_is_uncompressed_sec1() {
        let result =
            verify_pdf_signature(ECDSA_P256_PDF).expect("P-256 PDF: verification should not error");
        // Uncompressed SEC1 P-256 point: 0x04 || 32-byte X || 32-byte Y = 65 bytes
        assert_eq!(
            result.public_key.len(),
            65,
            "P-256 public_key should be 65 bytes"
        );
        assert_eq!(
            result.public_key[0], 0x04,
            "P-256 public_key should start with 0x04"
        );
    }

    #[test]
    fn test_ecdsa_p256_pdf_message_digest_is_sha256() {
        let result =
            verify_pdf_signature(ECDSA_P256_PDF).expect("P-256 PDF: verification should not error");
        assert_eq!(
            result.message_digest.len(),
            32,
            "SHA-256 digest should be 32 bytes"
        );
    }

    #[test]
    fn test_ecdsa_p256_pdf_tampered_fails() {
        let mut tampered = ECDSA_P256_PDF.to_vec();
        tampered[200] ^= 0xFF;
        let result = verify_pdf_signature(&tampered);
        match result {
            Ok(PdfSignatureResult {
                is_valid: false, ..
            }) => {}
            Ok(PdfSignatureResult { is_valid: true, .. }) => {
                panic!("Tampered PDF should NOT verify as valid")
            }
            Err(_) => {}
        }
    }
}
use hex::FromHexError;
use simple_asn1::{ASN1DecodeErr, OID};
use thiserror::Error;

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

#[derive(Debug, Error)]
pub enum SignedBytesError {
    #[error("PDF is not digitally signed: /ByteRange not found")]
    ByteRangeNotFound,
    #[error("PDF is not digitally signed: ByteRange '[' not found")]
    ByteRangeStartMissing,
    #[error("PDF is not digitally signed: ByteRange ']' not found")]
    ByteRangeEndMissing,
    #[error("Invalid ByteRange data")]
    InvalidByteRangeUtf8,
    #[error("Expected exactly 4 numbers inside ByteRange")]
    InvalidByteRangeCount,
    #[error("ByteRange values out of bounds")]
    ByteRangeOutOfBounds,
    #[error("Contents not found after ByteRange")]
    ContentsNotFound,
    #[error("Start '<' not found after Contents")]
    ContentsStartMissing,
    #[error("End '>' not found after Contents")]
    ContentsEndMissing,
    #[error("Invalid hex in Contents")]
    InvalidContentsUtf8,
    #[error("Contents hex parse error: {0}")]
    ContentsHexDecode(#[from] FromHexError),
}

pub type SignedBytesResult<T> = Result<T, SignedBytesError>;

#[derive(Debug, Error)]
pub enum Pkcs7Error {
    #[error("DER parse error: {0}")]
    Der(#[from] ASN1DecodeErr),
    #[error("PKCS#7 structure error: {0}")]
    Structure(String),
    #[error("Unsupported digest algorithm OID: {0:?}")]
    UnsupportedDigestOid(OID),
    #[error("messageDigest attribute (OID 1.2.840.113549.1.9.4) not found")]
    MissingMessageDigest,
}

impl Pkcs7Error {
    pub fn structure(msg: impl Into<String>) -> Self {
        Pkcs7Error::Structure(msg.into())
    }
}

pub type Pkcs7Result<T> = Result<T, Pkcs7Error>;

#[derive(Debug, Error)]
pub enum SignatureValidationError {
    #[error(transparent)]
    SignedBytes(#[from] SignedBytesError),
    #[error(transparent)]
    Pkcs7(#[from] Pkcs7Error),
    #[error("Unsupported signature algorithm for hash calculation: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    #[error("Message digest mismatch")]
    MessageDigestMismatch {
        expected: Vec<u8>,
        calculated: Vec<u8>,
    },
    #[error("Failed to construct RSA public key: {0}")]
    InvalidPublicKey(String),
    #[error("RSA signature verification error: {0}")]
    SignatureVerification(String),
}

pub type SignatureResult<T> = Result<T, SignatureValidationError>;

/// Metadata returned after verifying a PDF signature.
///
/// `is_valid` indicates whether the signature check succeeded.
/// `message_digest` is the hash that the signer committed to in the PDF (length determined by the
/// signature algorithm).
/// `public_key` of pdf signer's certificate in DER format.
#[derive(Debug, Clone)]
pub struct PdfSignatureResult {
    pub is_valid: bool,
    pub message_digest: Vec<u8>,
    pub public_key: Vec<u8>,
}

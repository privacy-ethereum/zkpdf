use pdf_core::PdfVerificationResult;

use alloy_primitives::{keccak256, B256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

pub const NULLIFIER_DOMAIN: &[u8] = b"zkpdf-nullifier-v0";

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bool substringMatches;
        bytes32 messageDigestHash;
        bytes32 signerKeyHash;
        bytes32 substringHash;
        bytes32 nullifier;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDFCircuitInput {
    pub pdf_bytes: Vec<u8>,
    pub page_number: u8,
    pub offset: u32,
    pub substring: String,
}

#[derive(Debug, Clone)]
pub struct PDFCircuitOutput {
    pub substring_matches: bool,
    pub message_digest_hash: B256,
    pub signer_key_hash: B256,
    pub substring_hash: B256,
    pub nullifier: B256,
}

impl From<PDFCircuitOutput> for PublicValuesStruct {
    fn from(value: PDFCircuitOutput) -> Self {
        PublicValuesStruct {
            substringMatches: value.substring_matches,
            messageDigestHash: value.message_digest_hash,
            signerKeyHash: value.signer_key_hash,
            substringHash: value.substring_hash,
            nullifier: value.nullifier,
        }
    }
}

impl PDFCircuitOutput {
    /// Construct a failure output (all zeros).
    pub fn failure() -> Self {
        Self {
            substring_matches: false,
            message_digest_hash: B256::ZERO,
            signer_key_hash: B256::ZERO,
            substring_hash: B256::ZERO,
            nullifier: B256::ZERO,
        }
    }

    /// Build a circuit output from a PDF verification result.
    pub fn from_verification(
        sub_string: &str,
        page_number: u8,
        offset: u32,
        verification_result: PdfVerificationResult,
    ) -> Self {
        let message_digest_hash = keccak256(&verification_result.signature.message_digest);
        let pub_key_hash = keccak256(verification_result.signature.public_key);
        let sub_string_hash = keccak256(sub_string.as_bytes());

        let nullifier = crate::nullifier::compute_nullifier(
            message_digest_hash.as_slice(),
            pub_key_hash.as_slice(),
            sub_string_hash.as_slice(),
            page_number,
            offset,
        );

        Self {
            substring_matches: verification_result.substring_matches,
            message_digest_hash,
            signer_key_hash: pub_key_hash,
            substring_hash: sub_string_hash,
            nullifier,
        }
    }
}

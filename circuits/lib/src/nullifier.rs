use alloy_primitives::keccak256;

use crate::types::NULLIFIER_DOMAIN;

pub fn compute_nullifier(
    message_digest_hash: &[u8],
    signer_key_hash: &[u8],
    substring_hash: &[u8],
    page_number: u8,
    offset: u32,
) -> alloy_primitives::B256 {
    const HASH_LEN: usize = 32;
    let mut preimage = Vec::with_capacity(NULLIFIER_DOMAIN.len() + HASH_LEN * 3 + 1 + 4);

    preimage.extend_from_slice(NULLIFIER_DOMAIN);
    preimage.extend_from_slice(message_digest_hash);
    preimage.extend_from_slice(signer_key_hash);
    preimage.extend_from_slice(substring_hash);
    preimage.push(page_number);
    preimage.extend_from_slice(&offset.to_be_bytes());

    keccak256(&preimage)
}

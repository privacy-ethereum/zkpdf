use std::str;

use crate::types::{SignedBytesError, SignedBytesResult};

struct ByteRange {
    offset1: usize,
    len1: usize,
    offset2: usize,
    len2: usize,
}

fn parse_byte_range(pdf_bytes: &[u8]) -> SignedBytesResult<ByteRange> {
    let br_pos = pdf_bytes
        .windows(b"/ByteRange".len())
        .position(|w| w == b"/ByteRange")
        .ok_or(SignedBytesError::ByteRangeNotFound)?;
    let br_start = pdf_bytes[br_pos..]
        .iter()
        .position(|&b| b == b'[')
        .ok_or(SignedBytesError::ByteRangeStartMissing)?
        + br_pos
        + 1;
    let br_end = pdf_bytes[br_start..]
        .iter()
        .position(|&b| b == b']')
        .ok_or(SignedBytesError::ByteRangeEndMissing)?
        + br_start;
    let br_str = str::from_utf8(&pdf_bytes[br_start..br_end])
        .map_err(|_| SignedBytesError::InvalidByteRangeUtf8)?;

    let nums: Vec<usize> = br_str
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .take(4)
        .collect();
    if nums.len() != 4 {
        return Err(SignedBytesError::InvalidByteRangeCount);
    }
    let [offset1, len1, offset2, len2] = [nums[0], nums[1], nums[2], nums[3]];

    if offset1 + len1 > pdf_bytes.len() || offset2 + len2 > pdf_bytes.len() {
        return Err(SignedBytesError::ByteRangeOutOfBounds);
    }

    Ok(ByteRange {
        offset1,
        len1,
        offset2,
        len2,
    })
}

fn extract_signed_data(pdf_bytes: &[u8], byte_range: &ByteRange) -> Vec<u8> {
    let mut signed_data = Vec::with_capacity(byte_range.len1 + byte_range.len2);
    signed_data
        .extend_from_slice(&pdf_bytes[byte_range.offset1..byte_range.offset1 + byte_range.len1]);
    signed_data
        .extend_from_slice(&pdf_bytes[byte_range.offset2..byte_range.offset2 + byte_range.len2]);
    signed_data
}

fn extract_signature_hex(pdf_bytes: &[u8], byte_range_pos: usize) -> SignedBytesResult<String> {
    const KEY: &[u8] = b"/Contents";
    let mut contents_pos = None;
    let mut cursor_pos = 0;

    let mut search_index = byte_range_pos;
    while search_index < pdf_bytes.len() {
        let slice = &pdf_bytes[search_index..];
        if let Some(offset) = slice.windows(KEY.len()).position(|w| w == KEY) {
            let pos = search_index + offset;
            let mut cursor = pos + KEY.len();
            while cursor < pdf_bytes.len() && pdf_bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < pdf_bytes.len() && pdf_bytes[cursor] == b'<' {
                contents_pos = Some(pos);
                cursor_pos = cursor;
                break;
            }
            search_index = pos + 1;
        } else {
            break;
        }
    }

    if contents_pos.is_none() {
        let mut search_end = byte_range_pos;
        while search_end > 0 {
            let slice = &pdf_bytes[..search_end];
            if let Some(pos) = slice.windows(KEY.len()).rposition(|w| w == KEY) {
                let mut cursor = pos + KEY.len();
                while cursor < pdf_bytes.len() && pdf_bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if cursor < pdf_bytes.len() && pdf_bytes[cursor] == b'<' {
                    contents_pos = Some(pos);
                    cursor_pos = cursor;
                    break;
                }
                search_end = pos;
            } else {
                break;
            }
        }
    }

    if contents_pos.is_none() {
        return Err(SignedBytesError::ContentsNotFound);
    }

    if cursor_pos >= pdf_bytes.len() || pdf_bytes[cursor_pos] != b'<' {
        return Err(SignedBytesError::ContentsStartMissing);
    }

    let hex_start = cursor_pos + 1;
    let hex_end = pdf_bytes[hex_start..]
        .iter()
        .position(|&b| b == b'>')
        .ok_or(SignedBytesError::ContentsEndMissing)?
        + hex_start;

    let hex_slice = &pdf_bytes[hex_start..hex_end];
    let hex_str = str::from_utf8(hex_slice).map_err(|_| SignedBytesError::InvalidContentsUtf8)?;
    let cleaned: String = hex_str.split_whitespace().collect();

    Ok(cleaned)
}

fn decode_signature_hex(hex_str: &str) -> SignedBytesResult<Vec<u8>> {
    let mut signature_der = hex::decode(hex_str)?;
    while signature_der.last() == Some(&0) {
        signature_der.pop();
    }
    Ok(signature_der)
}

pub fn get_signature_der(pdf_bytes: &[u8]) -> SignedBytesResult<(Vec<u8>, Vec<u8>)> {
    let byte_range = parse_byte_range(pdf_bytes)?;
    let signed_data = extract_signed_data(pdf_bytes, &byte_range);

    let br_pos = pdf_bytes
        .windows(b"/ByteRange".len())
        .position(|w| w == b"/ByteRange")
        .ok_or(SignedBytesError::ByteRangeNotFound)?;

    let hex_str = extract_signature_hex(pdf_bytes, br_pos)?;
    let signature_der = decode_signature_hex(&hex_str)?;

    Ok((signature_der, signed_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Digest;

    static SAMPLE_PDF_BYTES: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed.pdf");
    static EXPECTED_SIG_BYTES: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed_ber.txt");

    #[test]
    fn sample_pdf_signature_and_hash() {
        let (signature_der, signed_data) =
            get_signature_der(&SAMPLE_PDF_BYTES).expect("Failed to get signed data");

        let expected_signature = std::str::from_utf8(&EXPECTED_SIG_BYTES)
            .expect("Failed to convert signature DER to UTF-8")
            .trim()
            .to_string();

        let mut hasher = sha1::Sha1::new();
        hasher.update(&signed_data);
        let hash = hasher.finalize();

        assert_eq!(
            hex::encode(&hash),
            "3f0047e6cb5b9bb089254b20d174445c3ba4f513"
        );

        assert_eq!(expected_signature, hex::encode(&signature_der));
    }

    #[cfg(feature = "private_tests")]
    mod private {
        use super::*;
        use sha2::Sha256;
        #[test]
        fn test_sha256_pdf_private() {
            let pdf_bytes: &[u8] = include_bytes!("../../samples-private/bank-cert.pdf");
            let (_, signed_data) =
                get_signature_der(&pdf_bytes).expect("failed to extract signed data");

            let mut hasher = Sha256::new();
            hasher.update(&signed_data);
            let digest = hasher.finalize();
            assert_eq!(
                hex::encode(digest),
                "8f4a45720f3076fe51cc4fd1b5b23387fa6bbfb463262e6095e3af62a039dea1"
            );
        }

        #[test]
        fn test_sha1_with_rsa_encryption_private() {
            let pdf_bytes: &[u8] = include_bytes!("../../samples-private/pan-cert.pdf");

            let (_, signed_data) =
                get_signature_der(&pdf_bytes).expect("failed to extract signed data");
            let mut hasher = Sha256::new();
            hasher.update(&signed_data);
            let digest = hasher.finalize();

            assert_eq!(
                hex::encode(digest),
                "a6c81c2d89d36a174273a4faa06fcfc91db574f572cfdf3a6518d08fb4eb4155"
            );
        }
    }
}

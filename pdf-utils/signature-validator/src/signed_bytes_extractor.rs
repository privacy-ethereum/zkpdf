use std::str;

struct ByteRange {
    offset1: usize,
    len1: usize,
    offset2: usize,
    len2: usize,
}

fn parse_byte_range(pdf_bytes: &[u8]) -> Result<ByteRange, &'static str> {
    let br_pos = pdf_bytes
        .windows(b"/ByteRange".len())
        .position(|w| w == b"/ByteRange")
        .ok_or("ByteRange not found")?;
    let br_start = pdf_bytes[br_pos..]
        .iter()
        .position(|&b| b == b'[')
        .ok_or("ByteRange '[' not found")?
        + br_pos
        + 1;
    let br_end = pdf_bytes[br_start..]
        .iter()
        .position(|&b| b == b']')
        .ok_or("ByteRange ']' not found")?
        + br_start;
    let br_str =
        str::from_utf8(&pdf_bytes[br_start..br_end]).map_err(|_| "Invalid ByteRange data")?;

    let nums: Vec<usize> = br_str
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .take(4)
        .collect();
    if nums.len() != 4 {
        return Err("Expected exactly 4 numbers inside ByteRange");
    }
    let [offset1, len1, offset2, len2] = [nums[0], nums[1], nums[2], nums[3]];

    if offset1 + len1 > pdf_bytes.len() || offset2 + len2 > pdf_bytes.len() {
        return Err("ByteRange values out of bounds");
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

fn extract_signature_hex(pdf_bytes: &[u8], byte_range_pos: usize) -> Result<String, &'static str> {
    let contents_pos = pdf_bytes[byte_range_pos..]
        .windows(b"/Contents".len())
        .position(|w| w == b"/Contents")
        .ok_or("Contents not found after ByteRange")?
        + byte_range_pos;
    let hex_start = pdf_bytes[contents_pos..]
        .iter()
        .position(|&b| b == b'<')
        .ok_or("Start '<' not found after Contents")?
        + contents_pos
        + 1;
    let hex_end = pdf_bytes[hex_start..]
        .iter()
        .position(|&b| b == b'>')
        .ok_or("End '>' not found after Contents")?
        + hex_start;

    str::from_utf8(&pdf_bytes[hex_start..hex_end])
        .map_err(|_| "Invalid hex in Contents")
        .map(|s| s.to_string())
}

fn decode_signature_hex(hex_str: &str) -> Result<Vec<u8>, &'static str> {
    let mut signature_der = hex::decode(hex_str).map_err(|_| "Contents hex parse error")?;
    while signature_der.last() == Some(&0) {
        signature_der.pop();
    }
    Ok(signature_der)
}

pub fn get_signature_der(pdf_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let byte_range = parse_byte_range(pdf_bytes)?;
    let signed_data = extract_signed_data(pdf_bytes, &byte_range);

    let br_pos = pdf_bytes
        .windows(b"/ByteRange".len())
        .position(|w| w == b"/ByteRange")
        .ok_or("ByteRange not found")?;

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
        use std::fs;
        use std::path::Path;
        #[test]
        fn test_sha256_pdf_private() {
            let private_file_path = Path::new("../../samples-private/bank-cert.pdf");
            if private_file_path.exists() {
                let pdf_bytes = fs::read(private_file_path).expect("Failed to read private PDF");
                let (_, signed_data) =
                    get_signature_der(&pdf_bytes).expect("failed to extract signed data");
                let mut hasher = Sha256::new();
                hasher.update(&signed_data);
                let digest = hasher.finalize();
                assert_eq!(
                    hex::encode(digest),
                    "8f4a45720f3076fe51cc4fd1b5b23387fa6bbfb463262e6095e3af62a039dea1"
                );
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
                let (_, signed_data) =
                    get_signature_der(&pdf_bytes).expect("failed to extract signed data");
                let mut hasher = Sha256::new(); // Assuming SHA256 for this test as well based on previous
                hasher.update(&signed_data);
                let digest = hasher.finalize();
                assert_eq!(
                    hex::encode(digest),
                    "a6c81c2d89d36a174273a4faa06fcfc91db574f572cfdf3a6518d08fb4eb4155"
                );
            } else {
                eprintln!("Skipping private test: '../../samples-private/pan-cert.pdf' not found.");
            }
        }
    }
}

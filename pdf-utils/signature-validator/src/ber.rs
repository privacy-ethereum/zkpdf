//! BER-to-DER transcoder
use crate::types::Pkcs7Error;

/// Transcode a BER indefinite-length byte sequence into DER.
/// The caller must ensure the input actually uses BER indefinite-length encoding (for example the outer element's length byte is `0x80`).
pub fn transcode_ber_to_der(input: &[u8]) -> Result<Vec<u8>, Pkcs7Error> {
    let mut output = Vec::with_capacity(input.len());
    transcode_one(input, 0, &mut output)?;
    Ok(output)
}

/// Transcode one TLV element from BER to DER, appending to `output`.
/// Returns the byte position immediately after the consumed element.
fn transcode_one(input: &[u8], start: usize, output: &mut Vec<u8>) -> Result<usize, Pkcs7Error> {
    let mut pos = start;

    // Tag
    if pos >= input.len() {
        return Err(Pkcs7Error::structure("BER: unexpected end of input at tag"));
    }
    let tag_start = pos;
    let tag_byte = input[pos];
    let constructed = (tag_byte & 0x20) != 0;
    pos += 1;

    // High-tag-number form (tag number >= 31)
    if (tag_byte & 0x1F) == 0x1F {
        while pos < input.len() {
            let b = input[pos];
            pos += 1;
            if (b & 0x80) == 0 {
                break;
            }
        }
    }
    let tag_bytes = &input[tag_start..pos];

    // Length
    if pos >= input.len() {
        return Err(Pkcs7Error::structure(
            "BER: unexpected end of input at length",
        ));
    }
    let length_byte = input[pos];
    pos += 1;

    if length_byte == 0x80 {
        // Indefinite length
        if !constructed {
            return Err(Pkcs7Error::structure(
                "BER: indefinite length on primitive type",
            ));
        }

        let mut inner = Vec::new();
        loop {
            if pos + 1 >= input.len() {
                return Err(Pkcs7Error::structure(
                    "BER: unterminated indefinite-length encoding",
                ));
            }
            // End-of-Contents marker
            if input[pos] == 0x00 && input[pos + 1] == 0x00 {
                pos += 2;
                break;
            }
            pos = transcode_one(input, pos, &mut inner)?;
        }

        output.extend_from_slice(tag_bytes);
        write_der_length(inner.len(), output);
        output.extend(inner);
    } else {
        // Re-encoding could alter length bytes inside signed attributes and break CMS hash verification.
        let content_len = if length_byte < 0x80 {
            length_byte as usize
        } else {
            let num_bytes = (length_byte & 0x7F) as usize;
            if num_bytes == 0 || pos + num_bytes > input.len() {
                return Err(Pkcs7Error::structure("BER: invalid definite length"));
            }
            let mut len = 0usize;
            for i in 0..num_bytes {
                len = len
                    .checked_shl(8)
                    .ok_or_else(|| Pkcs7Error::structure("BER: length overflow"))?
                    | (input[pos + i] as usize);
            }
            pos += num_bytes;
            len
        };

        if pos + content_len > input.len() {
            return Err(Pkcs7Error::structure(
                "BER: content length exceeds input",
            ));
        }
        pos += content_len;

        // Copy from tag_start through end of content (preserves original encoding)
        output.extend_from_slice(&input[tag_start..pos]);
    }

    Ok(pos)
}

/// Encode `len` as a DER definite-length field.
fn write_der_length(len: usize, output: &mut Vec<u8>) {
    if len < 0x80 {
        output.push(len as u8);
    } else if len <= 0xFF {
        output.push(0x81);
        output.push(len as u8);
    } else if len <= 0xFFFF {
        output.push(0x82);
        output.push((len >> 8) as u8);
        output.push((len & 0xFF) as u8);
    } else if len <= 0xFF_FFFF {
        output.push(0x83);
        output.push((len >> 16) as u8);
        output.push((len >> 8) as u8);
        output.push((len & 0xFF) as u8);
    } else {
        output.push(0x84);
        output.push((len >> 24) as u8);
        output.push((len >> 16) as u8);
        output.push((len >> 8) as u8);
        output.push((len & 0xFF) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_indefinite_length() {
        // SEQUENCE(indef) { INTEGER 1, INTEGER 2 } EOC
        let ber = vec![
            0x30, 0x80, // SEQUENCE indefinite
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x02, // INTEGER 2
            0x00, 0x00, // EOC
        ];
        let expected = vec![
            0x30, 0x06, // SEQUENCE length 6
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x02, // INTEGER 2
        ];
        assert_eq!(transcode_ber_to_der(&ber).unwrap(), expected);
    }

    #[test]
    fn nested_indefinite_length() {
        // SEQUENCE(indef) { SEQUENCE(indef) { INTEGER 5 } EOC } EOC
        let ber = vec![
            0x30, 0x80, // outer
            0x30, 0x80, // inner
            0x02, 0x01, 0x05, // INTEGER 5
            0x00, 0x00, // inner EOC
            0x00, 0x00, // outer EOC
        ];
        let expected = vec![
            0x30, 0x05, // outer SEQUENCE length 5
            0x30, 0x03, // inner SEQUENCE length 3
            0x02, 0x01, 0x05,
        ];
        assert_eq!(transcode_ber_to_der(&ber).unwrap(), expected);
    }

    #[test]
    fn mixed_definite_and_indefinite() {
        // SEQUENCE(indef) { SET(def,3) { INT 1 }, INT 2 } EOC
        let ber = vec![
            0x30, 0x80, // SEQUENCE indefinite
            0x31, 0x03, 0x02, 0x01, 0x01, // SET definite
            0x02, 0x01, 0x02, // INTEGER 2
            0x00, 0x00,
        ];
        let expected = vec![
            0x30, 0x08, // SEQUENCE length 8
            0x31, 0x03, 0x02, 0x01, 0x01, // SET unchanged
            0x02, 0x01, 0x02,
        ];
        assert_eq!(transcode_ber_to_der(&ber).unwrap(), expected);
    }

    #[test]
    fn context_specific_indefinite() {
        // SEQUENCE(indef) { OID, [0](indef) { SEQUENCE(indef) { INT 3 } EOC } EOC } EOC
        let ber = vec![
            0x30, 0x80, //
            0x06, 0x01, 0x01, // OID
            0xA0, 0x80, // [0] indefinite
            0x30, 0x80, // SEQUENCE indefinite
            0x02, 0x01, 0x03, // INTEGER 3
            0x00, 0x00, // SEQUENCE EOC
            0x00, 0x00, // [0] EOC
            0x00, 0x00, // outer EOC
        ];
        let expected = vec![
            0x30, 0x0A, // SEQUENCE length 10
            0x06, 0x01, 0x01, // OID
            0xA0, 0x05, // [0] length 5
            0x30, 0x03, // SEQUENCE length 3
            0x02, 0x01, 0x03,
        ];
        assert_eq!(transcode_ber_to_der(&ber).unwrap(), expected);
    }

    #[test]
    fn empty_indefinite_sequence() {
        let ber = vec![0x30, 0x80, 0x00, 0x00];
        let expected = vec![0x30, 0x00];
        assert_eq!(transcode_ber_to_der(&ber).unwrap(), expected);
    }

    #[test]
    fn unterminated_indefinite_is_error() {
        let ber = vec![0x30, 0x80, 0x02, 0x01, 0x01];
        assert!(transcode_ber_to_der(&ber).is_err());
    }
}

use std::collections::{BTreeMap, HashMap};

use crate::{
    encoding::{
        glyph_to_unicode, mac_expert_to_unicode, mac_roman_to_unicode, pdf_doc_to_unicode,
        standard_to_unicode, winansi_to_unicode,
    },
    types::PdfFont,
};

/// Split a line that may contain hex values with or without spaces
/// e.g., "<0003><0003><0020>" or "<0003> <0003> <0020>" or mixed
fn split_hex_values(line: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_bracket = false;

    for ch in line.chars() {
        match ch {
            '<' => {
                if in_bracket && !current.is_empty() {
                    // New bracket while in one, save the previous
                    result.push(format!("<{}>", current));
                    current.clear();
                }
                in_bracket = true;
            }
            '>' => {
                if in_bracket {
                    result.push(format!("<{}>", current));
                    current.clear();
                    in_bracket = false;
                }
            }
            '[' | ']' => {
                // Handle array markers
                result.push(ch.to_string());
            }
            ' ' | '\t' => {
                // Whitespace, ignore unless inside brackets
                if in_bracket {
                    current.push(ch);
                }
            }
            _ => {
                if in_bracket {
                    current.push(ch);
                } else if !ch.is_whitespace() {
                    // Non-bracketed content (shouldn't happen in well-formed CMap)
                    current.push(ch);
                }
            }
        }
    }

    // Handle any remaining content
    if in_bracket && !current.is_empty() {
        result.push(format!("<{}>", current));
    } else if !current.is_empty() {
        result.push(current);
    }

    result
}

// Use HashMap from std if available, otherwise use BTreeMap as a fallback for no_std
// #[cfg(feature = "std")]
// #[cfg(not(feature = "std"))]
// type HashMap<K, V> = BTreeMap<K, V>;

// parse ToUnicode CMap content to a mapping from character codes to Unicode strings
pub fn parse_cmap(cmap_data: &[u8]) -> HashMap<u32, String> {
    let mut map = BTreeMap::new();
    let text = match core::str::from_utf8(cmap_data) {
        Ok(s) => s,
        Err(_) => &String::from_utf8_lossy(cmap_data).into_owned(),
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if line.ends_with("beginbfchar") {
            i += 1;
            while i < lines.len() && !lines[i].trim_end().ends_with("endbfchar") {
                let l = lines[i].trim();
                //  <src> <dst>
                if l.starts_with('<') {
                    let parts = split_hex_values(l);
                    if parts.len() >= 2 {
                        let src = parts[0].trim_matches(|c| c == '<' || c == '>');
                        let dst = parts[1].trim_matches(|c| c == '<' || c == '>');
                        if let Ok(src_code) = u32::from_str_radix(src, 16) {
                            if let Some(dst_str) = parse_cmap_hex_to_string(dst) {
                                map.insert(src_code, dst_str);
                            }
                        }
                    }
                }
                i += 1;
            }
        } else if line.ends_with("beginbfrange") {
            i += 1;
            while i < lines.len() && !lines[i].trim_end().ends_with("endbfrange") {
                let l = lines[i].trim();
                // Format cases:
                // <start> <end> <dst>
                // or <start> <end> [<dst1> <dst2> ...]
                if l.starts_with('<') {
                    let parts = split_hex_values(l);
                    if parts.len() >= 3 {
                        let start_hex = parts[0].trim_matches(|c| c == '<' || c == '>');
                        let end_hex = parts[1].trim_matches(|c| c == '<' || c == '>');
                        if let (Ok(start_code), Ok(end_code)) = (
                            u32::from_str_radix(start_hex, 16),
                            u32::from_str_radix(end_hex, 16),
                        ) {
                            if parts[2] == "[" {
                                // Collect hex values between [ and ]
                                let mut j = 3; // Start after the [
                                let mut cur_code = start_code;

                                while j < parts.len() && parts[j] != "]" {
                                    if parts[j].starts_with("<") {
                                        let dst = parts[j].trim_matches(|c| c == '<' || c == '>');
                                        if let Some(dst_str) = parse_cmap_hex_to_string(dst) {
                                            map.insert(cur_code, dst_str);
                                        }
                                        cur_code += 1;
                                        if cur_code > end_code {
                                            break;
                                        }
                                    }
                                    j += 1;
                                }
                            } else {
                                //range mapping: <start> <end> <destStart>
                                let dest_start_hex =
                                    parts[2].trim_matches(|c| c == '<' || c == '>');
                                if let Some(dest_start_str) =
                                    parse_cmap_hex_to_string(dest_start_hex)
                                {
                                    let mut dest_start_codes: Vec<u32> =
                                        dest_start_str.chars().map(|ch| ch as u32).collect();
                                    for code in start_code..=end_code {
                                        let dest_string: String = dest_start_codes
                                            .iter()
                                            .map(|&u| char::from_u32(u).unwrap_or('?'))
                                            .collect();
                                        map.insert(code, dest_string);
                                        if let Some(last) = dest_start_codes.last_mut() {
                                            *last += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    map.into_iter().collect()
}

fn parse_cmap_hex_to_string(hex: &str) -> Option<String> {
    if hex.is_empty() {
        return Some(String::new());
    }
    if hex.len() % 4 != 0 {
        return None;
    }

    let chunks: Vec<&[u8]> = hex.as_bytes().chunks(4).collect();
    let mut out = String::new();
    let mut i = 0;

    while i < chunks.len() {
        let chunk = chunks[i];
        if chunk.len() < 4 {
            break;
        }
        let part = core::str::from_utf8(chunk).ok()?;
        let code = u16::from_str_radix(part, 16).ok()?;

        if (0xD800..=0xDBFF).contains(&code) {
            if i + 1 < chunks.len() {
                let next_part = core::str::from_utf8(chunks[i + 1]).ok()?;
                if let Ok(low) = u16::from_str_radix(next_part, 16) {
                    if (0xDC00..=0xDFFF).contains(&low) {
                        let combined =
                            0x10000 + (((code - 0xD800) as u32) << 10) + ((low - 0xDC00) as u32);
                        if let Some(ch) = char::from_u32(combined) {
                            out.push(ch);
                            i += 2;
                            continue;
                        }
                    }
                }
            }
            out.push('�');
            i += 1;
            continue;
        } else if (0xDC00..=0xDFFF).contains(&code) {
            out.push('�');
        } else if let Some(ch) = char::from_u32(code as u32) {
            out.push(ch);
        } else {
            out.push('�');
        }
        i += 1;
    }

    Some(out)
}

pub fn cmap_decode_bytes(bytes: &[u8], cmap: &HashMap<u32, String>, is_cid: bool) -> String {
    let mut result = String::new();
    if is_cid {
        // For CID fonts, codes are typically 2-byte sequences.
        let mut i = 0;
        while i < bytes.len() {
            let code = if i + 1 < bytes.len() {
                ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32)
            } else {
                bytes[i] as u32
            };
            i += 2;

            if let Some(txt) = cmap.get(&code) {
                result.push_str(txt);
            } else {
                result.push('�');
            }
        }
    } else {
        for &b in bytes {
            if let Some(txt) = cmap.get(&(b as u32)) {
                result.push_str(txt);
            } else {
                result.push('�');
            }
        }
    }
    result
}

pub fn decode_bytes(bytes: &[u8], font: &PdfFont) -> String {
    if let Some(cmap) = &font.to_unicode_map {
        let is_cid = font.subtype.as_deref() == Some("Type0");
        return cmap_decode_bytes(bytes, cmap, is_cid);
    }
    base_encode_bytes(bytes, font)
}

fn base_encode_bytes(bytes: &[u8], font: &PdfFont) -> String {
    let mut result = String::new();
    for &b in bytes {
        let code = b as u32;
        let mut decoded = false;

        if let Some(diffs) = &font.differences {
            if let Some(glyph_name) = diffs.get(&code) {
                match glyph_to_unicode(glyph_name) {
                    Some(ch) => {
                        result.push(ch);
                        decoded = true;
                    }
                    _ => (),
                }
            }
        }

        if decoded {
            continue;
        }

        let ch = match font.encoding.as_deref() {
            Some("WinAnsiEncoding") => winansi_to_unicode(b),
            Some("MacRomanEncoding") => mac_roman_to_unicode(b),
            Some("MacExpertEncoding") => mac_expert_to_unicode(b),
            Some("StandardEncoding") => standard_to_unicode(b),
            Some("PDFDocEncoding") => pdf_doc_to_unicode(b),
            _ => {
                if font.subtype.as_deref() == Some("Type1") {
                    standard_to_unicode(b)
                } else {
                    if b < 128 {
                        b as char
                    } else {
                        '�'
                    }
                }
            }
        };

        if ch != '\0' && ch != '�' {
            result.push(ch);
        }
    }
    result
}

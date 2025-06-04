use std::str;

use crate::types::Token;

pub fn fold_array_tokens(tokens: Vec<Token>) -> Vec<Token> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if let Token::ArrayStart = &tokens[i] {
            let mut arr_elems = Vec::new();
            i += 1;
            let mut depth = 1;
            while i < tokens.len() && depth > 0 {
                match &tokens[i] {
                    Token::ArrayStart => depth += 1,
                    Token::ArrayEnd => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                arr_elems.push(tokens[i].clone());
                i += 1;
            }
            result.push(Token::Array(fold_array_tokens(arr_elems)));
        } else {
            result.push(tokens[i].clone());
        }
        i += 1;
    }
    result
}

pub fn parse_literal_string(data: &[u8], start_index: usize) -> (Vec<u8>, usize) {
    let mut result = Vec::new();
    let mut i = start_index + 1;
    let mut nesting = 0;
    while i < data.len() {
        let byte = data[i];
        if byte == b'(' {
            nesting += 1;
            result.push(byte);
            i += 1;
        } else if byte == b')' {
            if nesting == 0 {
                i += 1;
                break;
            }
            nesting -= 1;
            result.push(byte);
            i += 1;
        } else if byte == b'\\' {
            i += 1;
            if i >= data.len() {
                break;
            }
            let next = data[i];
            match next {
                b'n' => {
                    result.push(b'\n');
                    i += 1;
                }
                b'r' => {
                    result.push(b'\r');
                    i += 1;
                }
                b't' => {
                    result.push(b'\t');
                    i += 1;
                }
                b'b' => {
                    result.push(0x08);
                    i += 1;
                }
                b'f' => {
                    result.push(0x0C);
                    i += 1;
                }
                b'(' | b')' | b'\\' => {
                    result.push(next);
                    i += 1;
                }
                b'\r' => {
                    i += 1;
                    if i < data.len() && data[i] == b'\n' {
                        i += 1;
                    }
                }
                b'\n' => {
                    i += 1;
                }
                b'0'..=b'7' => {
                    let mut octal = 0;
                    let mut count = 0;
                    while count < 3 && i < data.len() {
                        let d = data[i];
                        if !(b'0'..=b'7').contains(&d) {
                            break;
                        }
                        octal = (octal * 8) + (d - b'0') as u32;
                        i += 1;
                        count += 1;
                    }
                    result.push((octal & 0xFF) as u8);
                }
                _ => {
                    result.push(next);
                    i += 1;
                }
            }
        } else {
            result.push(byte);
            i += 1;
        }
    }
    (result, i)
}

pub fn parse_hex_string(data: &[u8], start_index: usize) -> (Vec<u8>, usize) {
    let mut result = Vec::new();
    let mut i = start_index + 1;
    let mut nibble: Option<u8> = None;
    while i < data.len() {
        let byte = data[i];
        if byte == b'>' {
            i += 1;
            break;
        }
        if byte.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if let Some(val) = hex_value(byte) {
            if let Some(n) = nibble {
                result.push((n << 4) | val);
                nibble = None;
            } else {
                nibble = Some(val);
            }
        }
        i += 1;
    }
    if let Some(val) = nibble {
        result.push(val << 4);
    }
    (result, i)
}

pub fn parse_name(data: &[u8], start_index: usize) -> (String, usize) {
    let mut i = start_index + 1;
    let start = i;
    while i < data.len() {
        let c = data[i];
        if c.is_ascii_whitespace() || is_delimiter(c) {
            break;
        }
        i += 1;
    }
    let name_bytes = &data[start..i];
    (String::from_utf8_lossy(name_bytes).to_string(), i)
}

pub fn parse_number(data: &[u8], start_index: usize) -> (f32, usize) {
    let mut i = start_index;
    let start = i;
    if data[i] == b'+' || data[i] == b'-' {
        i += 1;
    }
    while i < data.len() && data[i].is_ascii_digit() {
        i += 1;
    }
    if i < data.len() && data[i] == b'.' {
        i += 1;
    }
    while i < data.len() && data[i].is_ascii_digit() {
        i += 1;
    }

    let num_str = str::from_utf8(&data[start..i]).unwrap_or("0");
    (num_str.parse::<f32>().unwrap_or(0.0), i)
}

pub fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}
pub fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + c - b'a'),
        b'A'..=b'F' => Some(10 + c - b'A'),
        _ => None,
    }
}

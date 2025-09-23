use std::collections::HashMap;

use crate::types::{PdfError, PdfObj};

pub struct Parser<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    pub len: usize,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Parser {
            data,
            pos: 0,
            len: data.len(),
        }
    }

    pub fn skip_whitespace_and_comments(&mut self) {
        while self.pos < self.len {
            let byte = self.data[self.pos];
            // whitespace characters: 0x00, HT(0x09), LF(0x0A), FF(0x0C), CR(0x0D), space(0x20)
            if byte == b'%' {
                while self.pos < self.len
                    && self.data[self.pos] != b'\n'
                    && self.data[self.pos] != b'\r'
                {
                    self.pos += 1;
                }
                continue;
            }
            match byte {
                0x00 | 0x09 | 0x0A | 0x0C | 0x0D | 0x20 => {
                    self.pos += 1;
                    continue;
                }
                _ => break,
            }
        }
    }

    // Parse a PDF name (starting after the initial '/')
    pub fn parse_name(&mut self) -> Result<PdfObj, PdfError> {
        if self.pos >= self.len || self.data[self.pos] != b'/' {
            return Err(PdfError::ParseError("Name must start with '/'"));
        }
        self.pos += 1;
        let mut name_bytes = Vec::new();
        while self.pos < self.len {
            let c = self.data[self.pos];
            if c == b'/'
                || c == b'%'
                || c == b'('
                || c == b')'
                || c == b'<'
                || c == b'>'
                || c == b'['
                || c == b']'
                || c == b'{'
                || c == b'}'
                || c.is_ascii_whitespace()
            {
                break;
            }
            if c == b'#' && self.pos + 2 < self.len {
                // two hex digits after '#'
                let hex1 = self.data[self.pos + 1];
                let hex2 = self.data[self.pos + 2];
                if let (Some(n1), Some(n2)) = (Parser::hex_value(hex1), Parser::hex_value(hex2)) {
                    name_bytes.push((n1 << 4) | n2);
                    self.pos += 3;
                    continue;
                }
            }
            name_bytes.push(c);
            self.pos += 1;
        }

        // PDF names are typically ASCII or PDFDocEncoding
        let name_str = match String::from_utf8(name_bytes) {
            Ok(s) => s,
            Err(e) => {
                // If not valid UTF-8, fall back to Latin-1 like conversion
                let bytes = e.into_bytes();
                bytes
                    .iter()
                    .map(|&b| if b < 128 { b as char } else { b as char })
                    .collect()
            }
        };
        Ok(PdfObj::Name(name_str))
    }

    // Parse a numeric value (integer or real)
    pub fn parse_number(&mut self) -> Result<PdfObj, PdfError> {
        self.skip_whitespace_and_comments();
        let start = self.pos;
        if start >= self.len {
            return Err(PdfError::ParseError("Unexpected EOF in number"));
        }
        let mut negative = false;
        if self.data[self.pos] == b'+' || self.data[self.pos] == b'-' {
            negative = self.data[self.pos] == b'-';
            self.pos += 1;
        }
        let mut int_value: i64 = 0;
        while self.pos < self.len && self.data[self.pos].is_ascii_digit() {
            int_value = int_value
                .saturating_mul(10)
                .saturating_add((self.data[self.pos] - b'0') as i64);
            self.pos += 1;
        }
        // Check if we have a fractional part
        let mut result: f64;
        if self.pos < self.len && self.data[self.pos] == b'.' {
            // Floating point number
            self.pos += 1;
            let mut frac_value: i64 = 0;
            let mut frac_divisor: f64 = 1.0;
            while self.pos < self.len && self.data[self.pos].is_ascii_digit() {
                frac_value = frac_value
                    .saturating_mul(10)
                    .saturating_add((self.data[self.pos] - b'0') as i64);
                frac_divisor *= 10.0;
                self.pos += 1;
            }
            result = (int_value as f64) + (frac_value as f64 / frac_divisor);
        } else {
            result = int_value as f64;
        }
        if negative {
            result = -result;
        }
        Ok(PdfObj::Number(result))
    }

    // Parse a literal string enclosed in parentheses
    pub fn parse_literal_string(&mut self) -> Result<PdfObj, PdfError> {
        if self.pos >= self.len || self.data[self.pos] != b'(' {
            return Err(PdfError::ParseError("String must start with '('"));
        }
        self.pos += 1;
        let mut string_bytes = Vec::new();
        let mut nesting = 1;
        while self.pos < self.len && nesting > 0 {
            let byte = self.data[self.pos];
            if byte == b'(' {
                nesting += 1;
                string_bytes.push(byte);
                self.pos += 1;
            } else if byte == b')' {
                nesting -= 1;
                if nesting == 0 {
                    self.pos += 1;
                    break;
                }
                string_bytes.push(byte);
                self.pos += 1;
            } else if byte == b'\\' {
                // esc char
                self.pos += 1;
                if self.pos >= self.len {
                    break; // malformed string
                }
                let next = self.data[self.pos];
                match next {
                    b'n' => {
                        string_bytes.push(b'\n');
                        self.pos += 1;
                    }
                    b'r' => {
                        string_bytes.push(b'\r');
                        self.pos += 1;
                    }
                    b't' => {
                        string_bytes.push(b'\t');
                        self.pos += 1;
                    }
                    b'b' => {
                        string_bytes.push(0x08);
                        self.pos += 1;
                    } // backspace
                    b'f' => {
                        string_bytes.push(0x0C);
                        self.pos += 1;
                    } // form feed
                    b'(' | b')' | b'\\' => {
                        string_bytes.push(next);
                        self.pos += 1;
                    }
                    b'\r' => {
                        // Line continuation after CR (optional LF)
                        self.pos += 1;
                        if self.pos < self.len && self.data[self.pos] == b'\n' {
                            self.pos += 1;
                        }
                    }
                    b'\n' => {
                        self.pos += 1;
                    }
                    b'0'..=b'7' => {
                        // octal sequence
                        let mut count = 0;
                        let octal_digit = (next - b'0') as u32;
                        let mut octal = octal_digit;
                        self.pos += 1;
                        count += 1;
                        while count < 3 && self.pos < self.len {
                            let d = self.data[self.pos];
                            if d < b'0' || d > b'7' {
                                break;
                            }
                            octal = (octal << 3) | ((d - b'0') as u32);
                            self.pos += 1;
                            count += 1;
                        }
                        string_bytes.push((octal & 0xFF) as u8);
                    }
                    _ => {
                        string_bytes.push(next);
                        self.pos += 1;
                    }
                }
            } else {
                string_bytes.push(byte);
                self.pos += 1;
            }
        }
        if nesting != 0 {
            return Err(PdfError::ParseError("Unterminated literal string"));
        }
        Ok(PdfObj::String(string_bytes))
    }

    // Parse a hex string enclosed in < >
    pub fn parse_hex_string(&mut self) -> Result<PdfObj, PdfError> {
        if self.pos >= self.len
            || self.data[self.pos] != b'<'
            || (self.pos + 1 < self.len && self.data[self.pos + 1] == b'<')
        {
            return Err(PdfError::ParseError(
                "Hex string must start with '<' and not followed by another '<'",
            ));
        }
        self.pos += 1;
        let mut string_bytes = Vec::new();
        let mut nibble: Option<u8> = None;
        while self.pos < self.len {
            let byte = self.data[self.pos];
            if byte == b'>' {
                self.pos += 1;
                break;
            }
            if byte.is_ascii_whitespace() || byte == b'%' {
                self.skip_whitespace_and_comments();
                continue;
            }
            if let Some(val) = Parser::hex_value(byte) {
                if nibble.is_none() {
                    nibble = Some(val);
                } else {
                    let combined = (nibble.unwrap() << 4) | val;
                    string_bytes.push(combined);
                    nibble = None;
                }
                self.pos += 1;
            } else {
                return Err(PdfError::ParseError("Invalid character in hex string"));
            }
        }
        if let Some(val) = nibble {
            string_bytes.push(val << 4);
        }
        Ok(PdfObj::String(string_bytes))
    }

    fn hex_value(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(10 + (c - b'a')),
            b'A'..=b'F' => Some(10 + (c - b'A')),
            _ => None,
        }
    }

    pub fn parse_value(&mut self) -> Result<PdfObj, PdfError> {
        self.skip_whitespace_and_comments();
        if self.pos >= self.len {
            return Err(PdfError::ParseError("Unexpected EOF while parsing value"));
        }
        let byte = self.data[self.pos];
        match byte {
            b'<' => {
                if self.pos + 1 < self.len && self.data[self.pos + 1] == b'<' {
                    // dict
                    self.pos += 2;
                    self.parse_dictionary()
                } else {
                    // hex val
                    self.parse_hex_string()
                }
            }
            b'[' => {
                // array
                self.pos += 1;
                let mut arr = Vec::new();
                loop {
                    self.skip_whitespace_and_comments();
                    if self.pos >= self.len {
                        return Err(PdfError::ParseError("Unterminated array"));
                    }
                    if self.data[self.pos] == b']' {
                        self.pos += 1;
                        break;
                    }
                    arr.push(self.parse_value()?);
                }
                Ok(PdfObj::Array(arr))
            }
            b'(' => {
                // literal string
                self.parse_literal_string()
            }
            b'/' => {
                // name
                self.parse_name()
            }
            b't' | b'f' | b'n' => {
                // can be true, false or null
                if self.remaining_starts_with(b"true") {
                    self.pos += 4;
                    Ok(PdfObj::Boolean(true))
                } else if self.remaining_starts_with(b"false") {
                    self.pos += 5;
                    Ok(PdfObj::Boolean(false))
                } else if self.remaining_starts_with(b"null") {
                    self.pos += 4;
                    Ok(PdfObj::Null)
                } else {
                    Err(PdfError::ParseError("Unexpected keyword"))
                }
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => {
                // Number or possibly a reference (object reference pattern: <int> <int> R)
                let save_pos = self.pos;
                let mut neg = false;
                if byte == b'+' || byte == b'-' {
                    neg = self.data[self.pos] == b'-';
                    self.pos += 1;
                }
                let mut obj_num: u32 = 0;
                let mut digits_count = 0;
                while self.pos < self.len && self.data[self.pos].is_ascii_digit() {
                    obj_num = obj_num
                        .wrapping_mul(10)
                        .wrapping_add((self.data[self.pos] - b'0') as u32);
                    digits_count += 1;
                    self.pos += 1;
                }
                let is_integer =
                    digits_count > 0 && (self.pos >= self.len || self.data[self.pos] != b'.');
                if !is_integer {
                    self.pos = save_pos;
                    return self.parse_number();
                }
                let pos_after_first = self.pos;
                self.skip_whitespace_and_comments();
                if self.pos < self.len && self.data[self.pos].is_ascii_digit() {
                    let mut gen_num: u16 = 0;
                    let mut gen_digits = 0;
                    while self.pos < self.len && self.data[self.pos].is_ascii_digit() {
                        gen_num = gen_num
                            .wrapping_mul(10)
                            .wrapping_add((self.data[self.pos] - b'0') as u16);
                        gen_digits += 1;
                        self.pos += 1;
                    }
                    self.skip_whitespace_and_comments();
                    if gen_digits > 0 && self.pos < self.len && self.data[self.pos] == b'R' {
                        //<obj_num> <gen_num> R
                        self.pos += 1;
                        return Ok(PdfObj::Reference((obj_num, gen_num)));
                    }
                }
                self.pos = pos_after_first;
                let num_val = if neg {
                    -(obj_num as i64) as f64
                } else {
                    obj_num as f64
                };
                Ok(PdfObj::Number(num_val))
            }
            _ => {
                while self.pos < self.len && !self.data[self.pos].is_ascii_whitespace() {
                    self.pos += 1;
                }
                Ok(PdfObj::Null)
            }
        }
    }

    // check if the upcoming bytes start with the given sequence
    pub fn remaining_starts_with(&self, seq: &[u8]) -> bool {
        let end = self.pos + seq.len();
        if end > self.len {
            return false;
        }
        if &self.data[self.pos..end] != seq {
            return false;
        }
        if end < self.len {
            let next = self.data[end];
            if !(next.is_ascii_whitespace()
                || matches!(next, b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')'))
            {
                return false;
            }
        }
        true
    }

    // Parse a dictionary (assuming initial '<<' already consumed)
    pub fn parse_dictionary(&mut self) -> Result<PdfObj, PdfError> {
        let mut dict = HashMap::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.pos < self.len && self.data[self.pos] == b'>' {
                if self.pos + 1 < self.len && self.data[self.pos + 1] == b'>' {
                    self.pos += 2;
                    break;
                } else {
                    return Err(PdfError::ParseError("Malformed dictionary end"));
                }
            }
            if self.pos >= self.len {
                return Err(PdfError::ParseError("Dictionary key is not a name"));
            }
            if self.data[self.pos] != b'/' {
                if self.remaining_starts_with(b">>") {
                    self.pos += 2;
                    break;
                } else {
                    self.pos += 1;
                    continue;
                }
            }
            let key_obj = self.parse_name()?;
            let key = if let PdfObj::Name(s) = key_obj {
                s
            } else {
                return Err(PdfError::ParseError("Invalid dictionary key"));
            };
            self.skip_whitespace_and_comments();
            // Parse value
            let value = self.parse_value()?;
            dict.insert(key, value);
        }
        Ok(PdfObj::Dictionary(dict))
    }
}

/// Map a glyph name to a Unicode character (for Differences).
pub fn glyph_to_unicode(name: &str) -> Option<char> {
    // Common glyphs:
    let mapping = [
        ("space", ' '),
        ("parenleft", '('),
        ("parenright", ')'),
        ("minus", '-'),
        ("period", '.'),
        ("comma", ','),
        ("colon", ':'),
        ("semicolon", ';'),
        ("question", '?'),
        ("exclam", '!'),
        ("trademark", '™'),
        ("Trademark", '™'),
        ("bullet", '•'),
        ("Euro", '€'),
        ("Euroglyph", '€'),
        ("yen", '¥'),
        ("florin", 'ƒ'),
        ("emdash", '—'),
        ("endash", '–'),
        ("quotedblleft", '“'),
        ("quotedblright", '”'),
        ("quoteleft", '‘'),
        ("quoteright", '’'),
        ("AE", 'Æ'),
        ("ae", 'æ'),
        ("OE", 'Œ'),
        ("oe", 'œ'),
        ("fi", 'ﬁ'),
        ("fl", 'ﬂ'),
        ("ffi", 'ﬃ'),
        ("ffl", 'ﬄ'),
        ("ff", 'ﬀ'),
        ("dotlessi", 'ı'),
        ("dotlessj", 'ȷ'),
        ("germandbls", 'ß'),
        ("registered", '®'),
        ("copyright", '©'),
        ("trademark", '™'),
        // ... more can be added as needed
    ];
    for (glyph, ch) in mapping.iter() {
        if glyph.eq_ignore_ascii_case(name) {
            return Some(*ch);
        }
    }
    // If not found, attempt basic single-letter names (like A, B, a, b, etc.)
    if name.len() == 1 {
        let c = name.chars().next().unwrap();
        return Some(c);
    }
    None
}

/// WinAnsi (CP1252) encoding mapping
pub fn winansi_to_unicode(byte: u8) -> char {
    // Map 0x00-0x7F directly (includes standard ASCII control and printable).
    if byte < 0x80 {
        return byte as char;
    }
    // Map 0x80-0x9F (C1 control range in CP1252 has additional symbols)
    match byte {
        0x80 => '€',
        0x82 => '‚',
        0x83 => 'ƒ',
        0x84 => '„',
        0x85 => '…',
        0x86 => '†',
        0x87 => '‡',
        0x88 => 'ˆ',
        0x89 => '‰',
        0x8A => 'Š',
        0x8B => '‹',
        0x8C => 'Œ',
        0x8E => 'Ž',
        0x91 => '‘',
        0x92 => '’',
        0x93 => '“',
        0x94 => '”',
        0x95 => '•',
        0x96 => '–',
        0x97 => '—',
        0x98 => '˜',
        0x99 => '™',
        0x9A => 'š',
        0x9B => '›',
        0x9C => 'œ',
        0x9E => 'ž',
        0x9F => 'Ÿ',
        // Undefined 0x81, 0x8D, 0x8F, 0x90, 0x9D -> return a placeholder (or \0 to skip)
        0x81 | 0x8D | 0x8F | 0x90 | 0x9D => '\0',
        _ => {
            // 0xA0-0xFF: identical to ISO-8859-1 (Latin-1)
            byte as char // in Rust, char from u8 160-255 will interpret as Unicode codepoint U+00A0 to U+00FF
        }
    }
}

/// MacRoman encoding mapping
pub fn mac_roman_to_unicode(byte: u8) -> char {
    // 0x00-0x7F: ASCII
    if byte < 0x80 {
        return byte as char;
    }
    // 0x80-0xFF: use MacRoman table (partial listing for brevity)
    match byte {
        0x80 => 'Ä',
        0x81 => 'Å',
        0x82 => 'Ç',
        0x83 => 'É',
        0x84 => 'Ñ',
        0x85 => 'Ö',
        0x86 => 'Ü',
        0x87 => 'á',
        0x88 => 'à',
        0x89 => 'â',
        0x8A => 'ä',
        0x8B => 'ã',
        0x8C => 'å',
        0x8D => 'ç',
        0x8E => 'é',
        0x8F => 'è',
        0x90 => 'ê',
        0x91 => 'ë',
        0x92 => 'í',
        0x93 => 'ì',
        0x94 => 'î',
        0x95 => 'ï',
        0x96 => 'ñ',
        0x97 => 'ó',
        0x98 => 'ò',
        0x99 => 'ô',
        0x9A => 'ö',
        0x9B => 'õ',
        0x9C => 'ú',
        0x9D => 'ù',
        0x9E => 'û',
        0x9F => 'ü',
        0xA0 => '†',
        0xA1 => '°',
        0xA2 => '¢',
        0xA3 => '£',
        0xA4 => '§',
        0xA5 => '•',
        0xA6 => '¶',
        0xA7 => 'ß',
        0xA8 => '®',
        0xA9 => '©',
        0xAA => '™',
        0xAB => '´',
        0xAC => '¨',
        0xAD => '≠',
        0xAE => 'Æ',
        0xAF => 'Ø',
        0xB0 => '∞',
        0xB1 => '±',
        0xB2 => '≤',
        0xB3 => '≥',
        0xB4 => '¥',
        0xB5 => 'µ',
        0xB6 => '∂',
        0xB7 => '∑',
        0xB8 => '∏',
        0xB9 => 'π',
        0xBA => '∫',
        0xBB => 'ª',
        0xBC => 'º',
        0xBD => 'Ω',
        0xBE => 'æ',
        0xBF => 'ø',
        0xC0 => '¿',
        0xC1 => '¡',
        0xC2 => '¬',
        0xC3 => '√',
        0xC4 => 'ƒ',
        0xC5 => '≈',
        0xC6 => '∆',
        0xC7 => '«',
        0xC8 => '»',
        0xC9 => '…',
        0xCA => '\u{00A0}', // no-break space
        0xCB => 'À',
        0xCC => 'Ã',
        0xCD => 'Õ',
        0xCE => 'Œ',
        0xCF => 'œ',
        0xD0 => '–',
        0xD1 => '—',
        0xD2 => '“',
        0xD3 => '”',
        0xD4 => '‘',
        0xD5 => '’',
        0xD6 => '÷',
        0xD7 => '◊',
        0xD8 => 'ÿ',
        0xD9 => 'Ÿ',
        0xDA => '⁄',
        0xDB => '€',
        0xDC => '‹',
        0xDD => '›',
        0xDE => 'ﬁ',
        0xDF => 'ﬂ',
        0xE0 => '‡',
        0xE1 => '·',
        0xE2 => '‚',
        0xE3 => '„',
        0xE4 => '‰',
        0xE5 => 'Â',
        0xE6 => 'Ê',
        0xE7 => 'Á',
        0xE8 => 'Ë',
        0xE9 => 'È',
        0xEA => 'Í',
        0xEB => 'Î',
        0xEC => 'Ï',
        0xED => 'Ì',
        0xEE => 'Ó',
        0xEF => 'Ô',
        0xF0 => '\u{F8FF}', // Apple logo (Private Use)
        0xF1 => 'Ò',
        0xF2 => 'Ú',
        0xF3 => 'Û',
        0xF4 => 'Ù',
        0xF5 => 'ı',
        0xF6 => 'ˆ',
        0xF7 => '˜',
        0xF8 => '¯',
        0xF9 => '˘',
        0xFA => '˙',
        0xFB => '˚',
        0xFC => '¸',
        0xFD => '˝',
        0xFE => '˛',
        0xFF => 'ˇ',
        _ => '\0',
    }
}

/// MacExpert encoding mapping
pub fn mac_expert_to_unicode(byte: u8) -> char {
    // MacExpertEncoding – map known glyphs to Unicode. Many glyphs are small caps or special.
    match byte {
        0x20 => ' ', // space
        0x21 => '!',
        0x22 => '\"',
        0x23 => '#',
        0x24 => '$',
        0x25 => '%',
        0x26 => '&',
        0x27 => '\'',
        0x28 => '(',
        0x29 => ')',
        0x2A => '*',
        0x2B => '+',
        0x2C => ',',
        0x2D => '-',
        0x2E => '.',
        0x2F => '/',
        0x30 => '0',
        0x31 => '1',
        0x32 => '2',
        0x33 => '3',
        0x34 => '4',
        0x35 => '5',
        0x36 => '6',
        0x37 => '7',
        0x38 => '8',
        0x39 => '9',
        // MacExpert unique glyphs (oldstyle figures, small caps, etc.)
        0x60 => '¹',
        0x61 => '¼',
        0x62 => '½',
        0x63 => '¾', // onedotenleader? fractions
        0x64 => '⁄', // fraction slash
        // Oldstyle digits (0x60-0x69?) – map to normal digits (already done above 0-9).
        // Superior (superscript) digits and letters:
        0xB0 => '¹',
        0xB1 => '²',
        0xB2 => '³',
        0xB3 => '⁴',
        0xB4 => '⁵',
        0xB5 => '⁶',
        0xB6 => '⁷',
        0xB7 => '⁸',
        0xB8 => '⁹',
        0xB9 => '⁰',
        // Inferior (subscript) digits:
        0xC0 => '₁',
        0xC1 => '₂',
        0xC2 => '₃',
        0xC3 => '₄',
        0xC4 => '₅',
        0xC5 => '₆',
        0xC6 => '₇',
        0xC7 => '₈',
        0xC8 => '₉',
        0xC9 => '₀',
        // Ligatures:
        0xDA => 'ﬁ',
        0xDB => 'ﬂ',
        0xDC | 0xDD | 0xDE => '?', // (if no direct Unicode for FF/ffi/ffl, these might appear as two chars or use Private Use; using string "FF"/"ffi" etc. not ideal in char context)
        // Small cap letters (we map to normal letters as uppercase for extraction):
        0xE0 => 'A',
        0xE1 => 'B',
        0xE2 => 'C',
        0xE3 => 'D',
        0xE4 => 'E',
        0xE5 => 'F',
        0xE6 => 'G',
        0xE7 => 'H',
        0xE8 => 'I',
        0xE9 => 'J',
        0xEA => 'K',
        0xEB => 'L',
        0xEC => 'M',
        0xED => 'N',
        0xEE => 'O',
        0xEF => 'P',
        0xF0 => 'Q',
        0xF1 => 'R',
        0xF2 => 'S',
        0xF3 => 'T',
        0xF4 => 'U',
        0xF5 => 'V',
        0xF6 => 'W',
        0xF7 => 'X',
        0xF8 => 'Y',
        0xF9 => 'Z',
        // (Note: MacExpert also includes small cap punctuation and ordinals, map them to normal punctuation or skip.)
        0xAA => '©',
        0xAF => '™',
        0xBC => '®',
        _ => '\0',
    }
}

/// StandardEncoding mapping (Adobe Standard Latin). We map common ligatures and symbols; rest is ASCII.
pub fn standard_to_unicode(byte: u8) -> char {
    // 0x00-0x7F: ASCII
    if byte < 0x80 {
        return byte as char;
    }
    match byte {
        0xA1 => '¡',
        0xA2 => '¢',
        0xA3 => '£',
        0xA4 => '¤',
        0xA5 => '¥',
        0xA7 => '§',
        0xA8 => '¨',
        0xA9 => '©',
        0xAA => 'ª',
        0xAB => '«',
        0xAC => '¬',
        0xAE => '®',
        0xAF => '¯',
        0xB0 => '°',
        0xB1 => '±',
        0xB2 => '²',
        0xB3 => '³',
        0xB4 => '´',
        0xB5 => 'µ',
        0xB6 => '¶',
        0xB7 => '·',
        0xB8 => '¸',
        0xB9 => '¹',
        0xBA => 'º',
        0xBB => '»',
        0xBC => '¼',
        0xBD => '½',
        0xBE => '¾',
        0xC0 => 'À',
        0xC1 => 'Á',
        0xC2 => 'Â',
        0xC3 => 'Ã',
        0xC4 => 'Ä',
        0xC5 => 'Å',
        0xC6 => 'Æ',
        0xC7 => 'Ç',
        0xC8 => 'È',
        0xC9 => 'É',
        0xCA => 'Ê',
        0xCB => 'Ë',
        0xCC => 'Ì',
        0xCD => 'Í',
        0xCE => 'Î',
        0xCF => 'Ï',
        0xD0 => 'Ð',
        0xD1 => 'Ñ',
        0xD2 => 'Ò',
        0xD3 => 'Ó',
        0xD4 => 'Ô',
        0xD5 => 'Õ',
        0xD6 => 'Ö',
        0xD7 => '×',
        0xD8 => 'Ø',
        0xD9 => 'Ù',
        0xDA => 'Ú',
        0xDB => 'Û',
        0xDC => 'Ü',
        0xDD => 'Ý',
        0xDE => 'Þ',
        0xDF => 'ß',
        0xE0 => 'à',
        0xE1 => 'á',
        0xE2 => 'â',
        0xE3 => 'ã',
        0xE4 => 'ä',
        0xE5 => 'å',
        0xE6 => 'æ',
        0xE7 => 'ç',
        0xE8 => 'è',
        0xE9 => 'é',
        0xEA => 'ê',
        0xEB => 'ë',
        0xEC => 'ì',
        0xED => 'í',
        0xEE => 'î',
        0xEF => 'ï',
        0xF0 => 'ð',
        0xF1 => 'ñ',
        0xF2 => 'ò',
        0xF3 => 'ó',
        0xF4 => 'ô',
        0xF5 => 'õ',
        0xF6 => 'ö',
        0xF7 => '÷',
        0xF8 => 'ø',
        0xF9 => 'ù',
        0xFA => 'ú',
        0xFB => 'û',
        0xFC => 'ü',
        0xFD => 'ý',
        0xFE => 'þ',
        0xFF => 'ÿ',
        // StandardEncoding might not actually include all above, but we map as Latin1 for safety.
        // Special ligatures present in Type1 standard fonts:
        // Note: 0xFF is already mapped to 'ÿ' above, so fi ligature would need a different code
        // If unknown, return placeholder:
        _ => '\0',
    }
}

/// PDFDocEncoding mapping (partial: mostly same as Latin-1 for 0x20-0x7E and some differences above).
pub fn pdf_doc_to_unicode(byte: u8) -> char {
    // 0x00-0x7F same as ASCII, 0xA0-0xFF mostly Latin-1 with a few differences (like 0x18->U+2020 etc., but those are control range).
    if byte < 0x80 {
        return byte as char;
    }
    // We'll implement only a few specific ones; for others, assume Latin-1.
    match byte {
        0x9F => '¥',        // in PDFDocEncoding 0x9F is Yen (where Latin-1 0x9F is undefined)
        0xA0 => '\u{20AC}', // 0xA0 in PDFDocEncoding is Euro (where Latin-1 0xA0 is NBSP)
        _ => {
            // Use Latin-1 as default
            byte as char
        }
    }
}

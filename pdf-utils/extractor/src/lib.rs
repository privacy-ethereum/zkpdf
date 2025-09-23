pub mod parser_utils;
pub mod types;

mod cmap;
mod encoding;
mod font;
mod parser;

extern crate alloc;

use crate::cmap::decode_bytes;
use crate::font::collect_fonts_from_resources;
use crate::parser::Parser;
use crate::parser_utils::{
    fold_array_tokens, is_delimiter, parse_hex_string, parse_literal_string, parse_name,
    parse_number,
};
use crate::types::{PageContent, PdfError, PdfFont, PdfObj, PdfStream, Token};
use alloc::string::String;
use alloc::vec::Vec;
use miniz_oxide::inflate::decompress_to_vec_zlib;
use std::collections::HashMap;
use std::collections::HashSet;
use std::str;

/// Extracts text from a PDF and returns per-page strings
pub fn extract_text(pdf_bytes: Vec<u8>) -> Result<Vec<String>, PdfError> {
    let (page_content, objects) = parse_pdf(&pdf_bytes)?;
    let text_per_page = extract_text_from_document(&page_content, &objects)
        .map_err(|_| PdfError::ParseError("text extraction failed"))?;
    Ok(text_per_page)
}

/// Extracts text from all pages of a document.
pub fn extract_text_from_document(
    pages: &[PageContent],
    objects: &HashMap<(u32, u16), PdfObj>,
) -> Result<Vec<String>, String> {
    let mut pages_text = Vec::new();
    for page in pages {
        pages_text.push(extract_text_from_page(page, objects));
    }
    Ok(pages_text)
}

pub fn extract_text_from_page(
    page: &PageContent,
    _objects: &HashMap<(u32, u16), PdfObj>,
) -> String {
    let mut output = String::new();
    let tokens = parse_content_tokens(&page.content_streams.concat());
    let mut visited = HashSet::new();
    extract_from_tokens(
        &tokens,
        &page.fonts,
        &page.resources,
        &mut output,
        _objects,
        &mut visited,
    );
    output
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

// Use a recursive function to traverse the Pages tree
fn traverse_pages(
    obj_id: (u32, u16),
    objects: &HashMap<(u32, u16), PdfObj>,
    inherited_resources: Option<&HashMap<String, PdfObj>>,
    result: &mut Vec<PageContent>,
    decompress: &dyn Fn(&[u8]) -> Result<Vec<u8>, PdfError>,
) -> Result<(), PdfError> {
    let obj = if obj_id == (0, 0) {
        return Err(PdfError::ParseError("Pages object missing"));
    } else {
        objects
            .get(&obj_id)
            .ok_or(PdfError::ParseError("Missing object in page tree"))?
    };
    match obj {
        PdfObj::Dictionary(dict) => {
            let type_name = dict.get("Type");
            if let Some(PdfObj::Name(type_str)) = type_name {
                if type_str == "Pages" {
                    let new_inherited_res =
                        if let Some(PdfObj::Dictionary(res_dict)) = dict.get("Resources") {
                            Some(res_dict)
                        } else if let Some(PdfObj::Reference(res_ref)) = dict.get("Resources") {
                            if let Some(PdfObj::Dictionary(res_dict)) = objects.get(res_ref) {
                                Some(res_dict)
                            } else {
                                inherited_resources
                            }
                        } else {
                            inherited_resources
                        };

                    let kids_obj = dict
                        .get("Kids")
                        .ok_or(PdfError::ParseError("Pages node missing Kids"))?;
                    let kids_list = match kids_obj {
                        PdfObj::Array(arr) => arr.clone(),
                        PdfObj::Reference(kid_ref) => {
                            if let Some(PdfObj::Array(arr)) = objects.get(kid_ref) {
                                arr.clone()
                            } else {
                                return Err(PdfError::ParseError("Kids reference is not an array"));
                            }
                        }
                        _ => return Err(PdfError::ParseError("Invalid Kids type")),
                    };
                    for kid in kids_list {
                        match kid {
                            PdfObj::Reference(child_id) => {
                                // Recurse for each kid
                                traverse_pages(
                                    child_id,
                                    objects,
                                    new_inherited_res.or(inherited_resources),
                                    result,
                                    &decompress,
                                )?;
                            }
                            PdfObj::Dictionary(ref child_dict) => {
                                if let Some(PdfObj::Name(t)) = child_dict.get("Type") {
                                    if t == "Page" {
                                        process_page_dict(
                                            child_dict,
                                            new_inherited_res.or(inherited_resources),
                                            objects,
                                            result,
                                            &decompress,
                                        )?;
                                    } else if t == "Pages" {
                                        traverse_pages(
                                            (0, 0),
                                            objects,
                                            new_inherited_res.or(inherited_resources),
                                            result,
                                            &decompress,
                                        )?;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                } else if type_str == "Page" {
                    process_page_dict(dict, inherited_resources, objects, result, &decompress)?;
                } else {
                    return Err(PdfError::ParseError("Unknown object in page tree"));
                }
            } else {
                return Err(PdfError::ParseError("Missing Type in object"));
            }
        }
        PdfObj::Stream(stream) => {
            if let Some(PdfObj::Name(t)) = stream.dict.get("Type") {
                if t == "Page" {
                    process_page_stream(stream, inherited_resources, objects, result, &decompress)?;
                } else if t == "Pages" {
                    return Err(PdfError::ParseError(
                        "Pages object in stream form is not supported",
                    ));
                }
            } else {
                return Err(PdfError::ParseError(
                    "Stream object in page tree lacks Type",
                ));
            }
        }
        _ => return Err(PdfError::ParseError("Invalid object in page tree")),
    }
    Ok(())
}

// Helper to process a page given as a dictionary (no direct content in object)
fn process_page_dict(
    page_dict: &HashMap<String, PdfObj>,
    inherited_res: Option<&HashMap<String, PdfObj>>,
    objects: &HashMap<(u32, u16), PdfObj>,
    result: &mut Vec<PageContent>,
    decompress: &dyn Fn(&[u8]) -> Result<Vec<u8>, PdfError>,
) -> Result<(), PdfError> {
    let empty_map = HashMap::new();
    let resources_dict = if let Some(PdfObj::Dictionary(res)) = page_dict.get("Resources") {
        res
    } else if let Some(PdfObj::Reference(res_ref)) = page_dict.get("Resources") {
        if let Some(PdfObj::Dictionary(res)) = objects.get(res_ref) {
            res
        } else {
            inherited_res.unwrap_or(&empty_map)
        }
    } else {
        inherited_res.unwrap_or(&empty_map)
    };
    let mut content_streams: Vec<Vec<u8>> = Vec::new();
    if let Some(content_obj) = page_dict.get("Contents") {
        match content_obj {
            PdfObj::Reference(stream_ref) => {
                if let Some(obj) = objects.get(stream_ref) {
                    match obj {
                        PdfObj::Stream(s) => {
                            if let Some(filter) = s.dict.get("Filter") {
                                handle_stream_filters(
                                    filter,
                                    &s.data,
                                    decompress,
                                    &mut content_streams,
                                )?;
                            } else {
                                content_streams.push(s.data.clone());
                            }
                        }
                        _ => {
                            return Err(PdfError::ParseError("Content reference is not a stream"));
                        }
                    }
                }
            }
            PdfObj::Array(arr) => {
                for item in arr {
                    if let PdfObj::Reference(stream_ref) = item {
                        if let Some(PdfObj::Stream(s)) = objects.get(stream_ref) {
                            if let Some(filter) = s.dict.get("Filter") {
                                handle_stream_filters(
                                    filter,
                                    &s.data,
                                    decompress,
                                    &mut content_streams,
                                )?;
                            } else {
                                content_streams.push(s.data.clone());
                            }
                        }
                    }
                }
            }
            PdfObj::Stream(s) => {
                if let Some(filter) = s.dict.get("Filter") {
                    handle_stream_filters(filter, &s.data, decompress, &mut content_streams)?;
                } else {
                    content_streams.push(s.data.clone());
                }
            }
            _ => {}
        }
    }

    let fonts_map = collect_fonts_from_resources(resources_dict, objects, decompress)?;
    result.push(PageContent {
        content_streams,
        fonts: fonts_map,
        resources: resources_dict.clone(),
    });
    Ok(())
}

// Helper to process a page represented as a stream object (Page dictionary + content in one)
fn process_page_stream(
    page_stream: &PdfStream,
    inherited_res: Option<&HashMap<String, PdfObj>>,
    objects: &HashMap<(u32, u16), PdfObj>,
    result: &mut Vec<PageContent>,
    decompress: &dyn Fn(&[u8]) -> Result<Vec<u8>, PdfError>,
) -> Result<(), PdfError> {
    let page_dict = &page_stream.dict;
    let resources_obj = page_dict.get("Resources");

    let empty_map = HashMap::new();
    let resources_dict = match resources_obj {
        Some(PdfObj::Dictionary(res)) => res,
        Some(PdfObj::Reference(res_ref)) => {
            if let Some(PdfObj::Dictionary(res)) = objects.get(res_ref) {
                res
            } else {
                inherited_res.unwrap_or(&empty_map)
            }
        }
        _ => inherited_res.unwrap_or(&empty_map),
    };

    let mut content_streams: Vec<Vec<u8>> = Vec::new();
    if let Some(filter) = page_stream.dict.get("Filter") {
        handle_stream_filters(filter, &page_stream.data, decompress, &mut content_streams)?;
    } else {
        content_streams.push(page_stream.data.clone());
    }

    let fonts_map = collect_fonts_from_resources(resources_dict, objects, decompress)?;
    result.push(PageContent {
        content_streams,
        fonts: fonts_map,
        resources: resources_dict.clone(),
    });
    Ok(())
}

pub fn handle_stream_filters(
    filter_obj: &PdfObj,
    data: &[u8],
    decompress: &dyn Fn(&[u8]) -> Result<Vec<u8>, PdfError>,
    output_streams: &mut Vec<Vec<u8>>,
) -> Result<(), PdfError> {
    match filter_obj {
        PdfObj::Name(name) => {
            if name == "FlateDecode" || name == "Flate" {
                // Single Flate decode
                let decompressed = decompress(data).map_err(|_| PdfError::DecompressionError)?;
                output_streams.push(decompressed);
            } else {
                // Unsupported single filter
                return Err(PdfError::ParseError("Unsupported filter"));
            }
        }
        PdfObj::Array(filters) => {
            // If multiple filters, handle only simplest case: a single Flate filter in array
            if filters.len() == 1 {
                return handle_stream_filters(&filters[0], data, decompress, output_streams);
            } else {
                return Err(PdfError::ParseError("Multiple filters not supported"));
            }
        }
        _ => {
            return Err(PdfError::ParseError("Invalid Filter entry"));
        }
    }
    Ok(())
}

// Parse an entire PDF byte slice and produce page content data
pub fn parse_pdf(data: &[u8]) -> Result<(Vec<PageContent>, HashMap<(u32, u16), PdfObj>), PdfError> {
    let mut parser = Parser::new(data);
    let mut objects: HashMap<(u32, u16), PdfObj> = HashMap::new();

    // Skip PDF header (e.g. %PDF-1.7)
    // The header line ends with LF or CRLF. Skip until we hit a line break after "%PDF"
    if parser.pos < parser.len && &parser.data[parser.pos..parser.pos.min(parser.len)] == b"%PDF" {
        // find end of line
        while parser.pos < parser.len
            && parser.data[parser.pos] != b'\n'
            && parser.data[parser.pos] != b'\r'
        {
            parser.pos += 1;
        }
        // skip newline(s)
        if parser.pos < parser.len && parser.data[parser.pos] == b'\r' {
            parser.pos += 1;
            if parser.pos < parser.len && parser.data[parser.pos] == b'\n' {
                parser.pos += 1;
            }
        } else if parser.pos < parser.len && parser.data[parser.pos] == b'\n' {
            parser.pos += 1;
        }
    }

    loop {
        parser.skip_whitespace_and_comments();
        if parser.pos >= parser.len {
            break;
        }

        if parser.remaining_starts_with(b"xref") || parser.remaining_starts_with(b"trailer") {
            break;
        }
        if parser.remaining_starts_with(b"startxref") {
            parser.pos += 9; // len("startxref")
            parser.skip_whitespace_and_comments();
            if parser.pos < parser.len {
                let _ = parser.parse_number();
            }
            parser.skip_whitespace_and_comments();
            if parser.remaining_starts_with(b"%%EOF") {
                parser.pos += 5;
            }
            continue;
        }
        //  "<obj_id> <gen_id> obj"
        let obj_id = match parser.parse_number()? {
            PdfObj::Number(num) => num as u32,
            _ => return Err(PdfError::ParseError("Invalid object id")),
        };
        parser.skip_whitespace_and_comments();
        let gen1 = match parser.parse_number()? {
            PdfObj::Number(num) => num as u16,
            _ => return Err(PdfError::ParseError("Invalid generation number")),
        };
        parser.skip_whitespace_and_comments();
        if !parser.remaining_starts_with(b"obj") {
            return Err(PdfError::ParseError("Missing 'obj' keyword"));
        }
        parser.pos += 3;
        parser.skip_whitespace_and_comments();
        let obj_value = if parser.pos < parser.len
            && parser.data[parser.pos] == b'<'
            && parser.pos + 1 < parser.len
            && parser.data[parser.pos + 1] == b'<'
        {
            parser.pos += 2;
            let dict_obj = parser.parse_dictionary()?;

            parser.skip_whitespace_and_comments();
            if parser.remaining_starts_with(b"stream") {
                parser.pos += 6;
                if parser.pos < parser.len && parser.data[parser.pos] == b'\r' {
                    parser.pos += 1;
                    if parser.pos < parser.len && parser.data[parser.pos] == b'\n' {
                        parser.pos += 1;
                    }
                } else if parser.pos < parser.len && parser.data[parser.pos] == b'\n' {
                    parser.pos += 1;
                }

                let stream_start = parser.pos;

                let mut length_opt: Option<usize> = None;
                if let PdfObj::Dictionary(ref d) = dict_obj {
                    if let Some(len_obj) = d.get("Length") {
                        match len_obj {
                            PdfObj::Number(n) => length_opt = Some(*n as usize),
                            PdfObj::Reference((obj, generation)) => {
                                if let Some(PdfObj::Number(n)) = objects.get(&(*obj, *generation)) {
                                    length_opt = Some(*n as usize);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let search_term = b"endstream";
                let search_len = search_term.len();

                let stream_data = if let Some(len) = length_opt {
                    if stream_start + len > parser.len {
                        return Err(PdfError::ParseError("Unexpected EOF in stream"));
                    }
                    let data_end = stream_start + len;
                    parser.pos = data_end;
                    if parser.pos < parser.len && parser.data[parser.pos] == b'\r' {
                        parser.pos += 1;
                        if parser.pos < parser.len && parser.data[parser.pos] == b'\n' {
                            parser.pos += 1;
                        }
                    } else if parser.pos < parser.len && parser.data[parser.pos] == b'\n' {
                        parser.pos += 1;
                    }
                    parser.skip_whitespace_and_comments();
                    if !parser.remaining_starts_with(search_term) {
                        return Err(PdfError::ParseError("Missing 'endstream'"));
                    }
                    parser.data[stream_start..data_end].to_vec()
                } else {
                    let mut endstream_index = None;
                    let mut i = stream_start;
                    while i + search_len <= parser.len {
                        if &parser.data[i..i + search_len] == search_term {
                            let prev_ok = if i == 0 {
                                true
                            } else {
                                let prev = parser.data[i - 1];
                                prev == b'\n' || prev == b'\r' || prev.is_ascii_whitespace()
                            };
                            let next_ok = if i + search_len >= parser.len {
                                true
                            } else if parser.data[i + search_len..].starts_with(b"endobj") {
                                true
                            } else {
                                let next = parser.data[i + search_len];
                                next.is_ascii_whitespace()
                            };
                            if prev_ok && next_ok {
                                endstream_index = Some(i);
                                break;
                            }
                        }
                        i += 1;
                    }
                    let end_idx =
                        endstream_index.ok_or(PdfError::ParseError("Missing 'endstream'"))?;
                    parser.pos = end_idx;
                    let mut data_end = end_idx;
                    while data_end > stream_start && parser.data[data_end - 1].is_ascii_whitespace()
                    {
                        data_end -= 1;
                    }
                    parser.data[stream_start..data_end].to_vec()
                };

                parser.pos += search_len;
                parser.skip_whitespace_and_comments();
                if !parser.remaining_starts_with(b"endobj") {
                    return Err(PdfError::ParseError("Missing 'endobj' after stream"));
                }
                parser.pos += 6;
                let dict = if let PdfObj::Dictionary(d) = dict_obj {
                    d
                } else {
                    HashMap::new()
                };
                let stream_obj = PdfStream {
                    dict,
                    data: stream_data,
                };

                if let Some(PdfObj::Name(ref t)) = stream_obj.dict.get("Type") {
                    if t == "ObjStm" {
                        if let (Some(PdfObj::Number(first)), Some(PdfObj::Number(n))) =
                            (stream_obj.dict.get("First"), stream_obj.dict.get("N"))
                        {
                            if let Ok(decompressed) = decompress_to_vec_zlib(&stream_obj.data) {
                                parse_obj_stream(
                                    &decompressed,
                                    *first as usize,
                                    *n as usize,
                                    &mut objects,
                                )?;
                            }
                        }
                    }
                }

                PdfObj::Stream(stream_obj)
            } else {
                // "endobj"
                parser.skip_whitespace_and_comments();
                if !parser.remaining_starts_with(b"endobj") {
                    return Err(PdfError::ParseError(
                        "Missing 'endobj' for dictionary object",
                    ));
                }
                parser.pos += 6;
                dict_obj
            }
        } else {
            let value_obj = parser.parse_value()?;
            parser.skip_whitespace_and_comments();
            if !parser.remaining_starts_with(b"endobj") {
                return Err(PdfError::ParseError("Missing 'endobj' for object"));
            }
            parser.pos += 6;
            value_obj
        };
        objects.insert((obj_id, gen1), obj_value);
    }

    let mut trailer_index = None;
    if parser.remaining_starts_with(b"trailer") {
        trailer_index = Some(parser.pos);
    } else {
        let data_bytes = parser.data;
        for i in (0..data_bytes.len().saturating_sub(7)).rev() {
            if data_bytes[i..].starts_with(b"trailer") {
                trailer_index = Some(i);
                break;
            }
        }
    }

    let trailer_dict = if let Some(idx) = trailer_index {
        parser.pos = idx;
        if parser.remaining_starts_with(b"trailer") {
            parser.pos += 7;
        }
        parser.skip_whitespace_and_comments();
        if !parser.remaining_starts_with(b"<<") {
            return Err(PdfError::ParseError("Trailer dictionary not found"));
        }
        parser.pos += 2;
        let trailer_dict_obj = parser.parse_dictionary()?;
        if let PdfObj::Dictionary(d) = trailer_dict_obj {
            d
        } else {
            return Err(PdfError::ParseError("Trailer is not a dictionary"));
        }
    } else {
        let mut dict_opt = None;
        for obj in objects.values() {
            if let PdfObj::Stream(s) = obj {
                if let Some(PdfObj::Name(t)) = s.dict.get("Type") {
                    if t == "XRef" && s.dict.get("Root").is_some() {
                        dict_opt = Some(s.dict.clone());
                        break;
                    }
                }
            }
        }
        dict_opt.ok_or(PdfError::ParseError("Trailer dictionary not found"))?
    };
    let root_obj = match trailer_dict.get("Root") {
        Some(PdfObj::Reference(obj_id)) => objects.get(obj_id).cloned(),
        Some(other) => Some(other.clone()),
        None => None,
    };
    let root_obj = root_obj.ok_or(PdfError::ParseError("Root object not found"))?;
    let pages_obj_id = match root_obj {
        PdfObj::Dictionary(ref m) => {
            match m.get("Pages") {
                Some(PdfObj::Reference(id)) => *id,
                Some(PdfObj::Dictionary(_)) => {
                    (0, 0) // use (0,0) as marker for embedded
                }
                _ => return Err(PdfError::ParseError("Pages reference not found in Catalog")),
            }
        }
        _ => return Err(PdfError::ParseError("Catalog object is not a dictionary")),
    };

    let mut result = Vec::new();

    if pages_obj_id != (0, 0) {
        traverse_pages(pages_obj_id, &objects, None, &mut result, &|bytes| {
            decompress_to_vec_zlib(bytes).map_err(|_| PdfError::DecompressionError)
        })?;
    } else {
        return Err(PdfError::ParseError(
            "Pages object embedded in catalog is not supported",
        ));
    }

    Ok((result, objects))
}

fn parse_obj_stream(
    data: &[u8],
    first: usize,
    count: usize,
    objects: &mut HashMap<(u32, u16), PdfObj>,
) -> Result<(), PdfError> {
    let mut parser = Parser::new(data);
    let mut headers = Vec::new();
    for _ in 0..count {
        let obj_num = match parser.parse_number()? {
            PdfObj::Number(n) => n as u32,
            _ => return Err(PdfError::ParseError("Invalid object number in ObjStm")),
        };
        parser.skip_whitespace_and_comments();
        let offset = match parser.parse_number()? {
            PdfObj::Number(n) => n as usize,
            _ => return Err(PdfError::ParseError("Invalid object offset in ObjStm")),
        };
        headers.push((obj_num, offset));
    }
    for i in 0..count {
        let start = first + headers[i].1;
        let end = if i + 1 < count {
            first + headers[i + 1].1
        } else {
            data.len()
        };
        let mut sub = Parser::new(&data[start..end]);
        let value = sub.parse_value()?;
        objects.insert((headers[i].0, 0), value);
    }
    Ok(())
}

fn parse_content_tokens(data: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' | 0x0C => {
                i += 1;
            }
            b'[' => {
                tokens.push(Token::ArrayStart);
                i += 1;
            }
            b']' => {
                tokens.push(Token::ArrayEnd);
                i += 1;
            }
            b'(' => {
                let (string_bytes, new_index) = parse_literal_string(data, i);
                tokens.push(Token::String(string_bytes));
                i = new_index;
            }
            b'<' => {
                if i + 1 < data.len() && data[i + 1] == b'<' {
                    i += 2;
                    let mut depth = 1;
                    while i < data.len() && depth > 0 {
                        if i + 1 < data.len() && &data[i..i + 2] == b"<<" {
                            depth += 1;
                            i += 2;
                        } else if i + 1 < data.len() && &data[i..i + 2] == b">>" {
                            depth -= 1;
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                } else {
                    let (bytes, new_index) = parse_hex_string(data, i);
                    tokens.push(Token::String(bytes));
                    i = new_index;
                }
            }
            b'/' => {
                let (name, new_index) = parse_name(data, i);
                tokens.push(Token::Name(name));
                i = new_index;
            }
            b'%' => {
                while i < data.len() && data[i] != b'\r' && data[i] != b'\n' {
                    i += 1;
                }
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => {
                let (number, new_index) = parse_number(data, i);
                tokens.push(Token::Number(number));
                i = new_index;
            }
            _ => {
                let start = i;
                while i < data.len() && !data[i].is_ascii_whitespace() && !is_delimiter(data[i]) {
                    i += 1;
                }
                if let Ok(op) = str::from_utf8(&data[start..i]) {
                    tokens.push(Token::Operator(op.to_string()));
                }
            }
        }
    }
    fold_array_tokens(tokens)
}

fn extract_from_tokens(
    tokens: &[Token],
    fonts: &HashMap<String, PdfFont>,
    resources: &HashMap<String, PdfObj>,
    output: &mut String,
    objects: &HashMap<(u32, u16), PdfObj>,
    visited: &mut HashSet<(u32, u16)>,
) {
    let mut in_text = false;
    let mut current_font: Option<&PdfFont> = None;
    let mut i = 0;

    while i < tokens.len() {
        if let Token::Operator(op) = &tokens[i] {
            match op.as_str() {
                "BT" => {
                    // Begin Text Object
                    in_text = true;
                }
                "ET" => {
                    // End Text Object
                    in_text = false;
                    current_font = None;
                    output.push('\n');
                }
                "Tf" => {
                    // Set text font+size: /F1 12 Tf
                    if i >= 2 {
                        if let Token::Name(font_name) = &tokens[i - 2] {
                            // Try to pick that font; otherwise warn
                            if let Some(f) = fonts.get(font_name) {
                                current_font = Some(f);
                            } else {
                                current_font = None;
                                // Font not found in resources
                            }
                        }
                    }
                }
                "Tj" | "'" | "\"" if in_text => {
                    if let Some(font) = current_font {
                        // If `'` or `"` used, start a new line
                        if op != "Tj" {
                            output.push('\n');
                        }
                        // The literal string to draw is immediately before the operator
                        if i >= 1 {
                            if let Token::String(bytes) = &tokens[i - 1] {
                                output.push_str(&decode_bytes(bytes, font));
                            }
                        }
                    }
                }
                "TJ" if in_text => {
                    // Show text with individual glyph positioning
                    if let Some(font) = current_font {
                        if i >= 1 {
                            if let Token::Array(arr) = &tokens[i - 1] {
                                for elem in arr {
                                    match elem {
                                        Token::String(bytes) => {
                                            output.push_str(&decode_bytes(bytes, font));
                                        }
                                        Token::Number(n) if *n < -200.0 => {
                                            output.push(' ');
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                "T*" if in_text => {
                    // Move to next line
                    output.push('\n');
                }
                "Td" | "TD" if in_text => {
                    // `Td`/`TD` moves the text position. When the vertical
                    // displacement parameter is non-zero it usually indicates
                    // a new line, otherwise it's just horizontal positioning
                    // for individual glyphs. Only insert a newline when the
                    // second operand (Ty) is not zero.
                    if i >= 2 {
                        if let (Token::Number(_tx), Token::Number(ty)) =
                            (&tokens[i - 2], &tokens[i - 1])
                        {
                            if *ty != 0.0 {
                                output.push('\n');
                            }
                        }
                    }
                }

                "Do" => {
                    // `Do` operator invokes an XObject
                    if i >= 1 {
                        if let Token::Name(xobj_name_from_token) = &tokens[i - 1] {
                            if let Some(xobjects_dict_obj) = resources.get("XObject") {
                                let resolved_xobjects_dict: Option<&HashMap<String, PdfObj>> =
                                    match xobjects_dict_obj {
                                        PdfObj::Dictionary(map) => Some(map),
                                        PdfObj::Reference(id) => objects.get(id).and_then(|obj| {
                                            if let PdfObj::Dictionary(map) = obj {
                                                Some(map)
                                            } else {
                                                None
                                            }
                                        }),
                                        _ => None,
                                    };

                                if let Some(actual_xobjects_map) = resolved_xobjects_dict {
                                    if let Some(original_xobj_entry) =
                                        actual_xobjects_map.get(xobj_name_from_token)
                                    {
                                        let mut object_id_for_visited_check: Option<(u32, u16)> =
                                            None;
                                        if let PdfObj::Reference(id) = original_xobj_entry {
                                            object_id_for_visited_check = Some(*id);
                                        }

                                        let form_stream_data: Option<&PdfStream> =
                                            match original_xobj_entry {
                                                PdfObj::Stream(s) => Some(s),
                                                PdfObj::Reference(id) => {
                                                    objects.get(id).and_then(|obj| {
                                                        if let PdfObj::Stream(s) = obj {
                                                            Some(s)
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                }
                                                _ => None,
                                            };

                                        if let Some(xf) = form_stream_data {
                                            let subtype =
                                                xf.dict.get("Subtype").and_then(|v| match v {
                                                    PdfObj::Name(name) => Some(name.as_str()),
                                                    _ => None,
                                                });

                                            if subtype == Some("Form") {
                                                let form_specific_resources: &HashMap<
                                                    String,
                                                    PdfObj,
                                                > = xf
                                                    .dict
                                                    .get("Resources")
                                                    .and_then(|res_obj| match res_obj {
                                                        PdfObj::Dictionary(map) => Some(map),
                                                        PdfObj::Reference(res_id) => {
                                                            objects.get(res_id).and_then(|o| {
                                                                if let PdfObj::Dictionary(map) = o {
                                                                    Some(map)
                                                                } else {
                                                                    None
                                                                }
                                                            })
                                                        }
                                                        _ => None,
                                                    })
                                                    .unwrap_or(resources);

                                                let form_content_bytes: Vec<u8>;
                                                if let Some(filter_obj) = xf.dict.get("Filter") {
                                                    let mut decompressed_holder: Vec<Vec<u8>> =
                                                        Vec::new();
                                                    match handle_stream_filters(
                                                        filter_obj,
                                                        &xf.data,
                                                        &|bytes_to_decompress| {
                                                            decompress_to_vec_zlib(
                                                                bytes_to_decompress,
                                                            )
                                                            .map_err(|_| {
                                                                PdfError::DecompressionError
                                                            })
                                                        },
                                                        &mut decompressed_holder,
                                                    ) {
                                                        Ok(_)
                                                            if !decompressed_holder.is_empty() =>
                                                        {
                                                            form_content_bytes =
                                                                decompressed_holder.remove(0);
                                                        }
                                                        Ok(_) => {
                                                            form_content_bytes = xf.data.clone();
                                                        }
                                                        Err(_e) => {
                                                            form_content_bytes = xf.data.clone();
                                                        }
                                                    }
                                                } else {
                                                    form_content_bytes = xf.data.clone();
                                                }

                                                let mut should_recurse = true;
                                                if let Some(id_to_check) =
                                                    object_id_for_visited_check
                                                {
                                                    if !visited.insert(id_to_check) {
                                                        should_recurse = false;
                                                    }
                                                }

                                                if should_recurse {
                                                    let nested_tokens =
                                                        parse_content_tokens(&form_content_bytes);

                                                    let form_fonts =
                                                        match collect_fonts_from_resources(
                                                            form_specific_resources,
                                                            objects,
                                                            &|b| {
                                                                decompress_to_vec_zlib(b).map_err(
                                                                    |_| {
                                                                        PdfError::DecompressionError
                                                                    },
                                                                )
                                                            },
                                                        ) {
                                                            Ok(ff) => ff,
                                                            Err(_e) => HashMap::new(),
                                                        };

                                                    extract_from_tokens(
                                                        &nested_tokens,
                                                        &form_fonts,
                                                        form_specific_resources,
                                                        output,
                                                        objects,
                                                        visited,
                                                    );

                                                    if let Some(id_visited) =
                                                        object_id_for_visited_check
                                                    {
                                                        visited.remove(&id_visited);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod extractor_tests {
    #[test]
    fn test_extract_text_public() {
        let pdf_data = include_bytes!("../../sample-pdfs/digitally_signed.pdf").to_vec();

        match super::extract_text(pdf_data) {
            Ok(text_per_page) => {
                assert!(!text_per_page.is_empty(), "No text extracted from PDF");
                assert!(
                    text_per_page[0] == "Sample Signed PDF Document",
                    "Expected text not found in the first page"
                );
            }
            Err(e) => panic!("Failed to extract PDF text: {:?}", e),
        }
    }

    #[test]
    fn extract_gst_template_pdf() {
        let pdf_data = include_bytes!("../../sample-pdfs/GST-certificate.pdf").to_vec();

        match super::extract_text(pdf_data) {
            Ok(text_per_page) => {
                assert!(text_per_page.len() == 3, "Expected at least 3 pages");
                assert!(!text_per_page.is_empty(), "No text extracted from PDF");
                assert!(
                    text_per_page[0].contains("Goods and Services Tax"),
                    "Expected text not found in the first page"
                );
            }
            Err(e) => panic!("Failed to extract PDF text: {:?}", e),
        }
    }
}

#[cfg(feature = "private_tests")]
mod test {
    use super::extract_text;

    #[test]
    fn text_extract_bank() {
        let pdf_data = include_bytes!("../../samples-private/bank-cert.pdf").to_vec();

        match extract_text(pdf_data) {
            Ok(text_per_page) => {
                for (i, text) in text_per_page.iter().enumerate() {
                    println!("Page {}: {}", i + 1, text);
                }
            }
            Err(e) => panic!("Failed to extract PDF text: {:?}", e),
        }
    }

    #[test]
    fn text_extract_pan() {
        let pdf_data = include_bytes!("../../samples-private/pan-cert.pdf").to_vec();

        match extract_text(pdf_data) {
            Ok(text_per_page) => {
                for (i, text) in text_per_page.iter().enumerate() {
                    println!("Page {}: {}", i + 1, text);
                }
            }
            Err(e) => panic!("Failed to extract PDF text: {:?}", e),
        }
    }
    #[test]
    fn text_extract_education() {
        let pdf_data = include_bytes!("../../samples-private/tenth_class.pdf").to_vec();

        match extract_text(pdf_data) {
            Ok(text_per_page) => {
                for (i, text) in text_per_page.iter().enumerate() {
                    println!("Page {}: {}", i + 1, text);
                }
            }
            Err(e) => panic!("Failed to extract PDF text: {:?}", e),
        }
    }

    #[test]
    fn text_extract_gst() {
        let pdf_data = include_bytes!("../../samples-private/GST_RC.pdf").to_vec();

        match extract_text(pdf_data) {
            Ok(text_per_page) => {
                for (i, text) in text_per_page.iter().enumerate() {
                    println!("Page {}: {}", i + 1, text);
                }
            }
            Err(e) => panic!("Failed to extract PDF text: {:?}", e),
        }
    }
}

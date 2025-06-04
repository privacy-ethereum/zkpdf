use std::collections::HashMap;

use crate::{
    cmap::parse_cmap,
    handle_stream_filters,
    types::{PdfError, PdfFont, PdfObj},
};

pub fn collect_fonts_from_resources(
    resources: &HashMap<String, PdfObj>,
    objects: &HashMap<(u32, u16), PdfObj>,
    decompress: &dyn Fn(&[u8]) -> Result<Vec<u8>, PdfError>,
) -> Result<HashMap<String, PdfFont>, PdfError> {
    let mut fonts_map: HashMap<String, PdfFont> = HashMap::new();
    if let Some(fonts_entry) = resources.get("Font") {
        let font_dict = match fonts_entry {
            PdfObj::Dictionary(map) => map,
            PdfObj::Reference(fid) => {
                if let Some(PdfObj::Dictionary(map)) = objects.get(fid) {
                    map
                } else {
                    &HashMap::new()
                }
            }
            _ => &HashMap::new(),
        };

        for (font_key, font_obj_ref) in font_dict {
            let font_obj = match font_obj_ref {
                PdfObj::Reference(fid) => objects.get(fid).cloned(),
                PdfObj::Dictionary(d) => Some(PdfObj::Dictionary(d.clone())),
                _ => None,
            };

            if let Some(PdfObj::Dictionary(font_dic)) = font_obj {
                let subtype = font_dic.get("Subtype").and_then(|v| match v {
                    PdfObj::Name(s) => Some(s.clone()),
                    _ => None,
                });
                let base_name = font_dic.get("BaseFont").and_then(|v| match v {
                    PdfObj::Name(s) => Some(s.clone()),
                    _ => None,
                });

                let mut encoding_name: Option<String> = None;
                let mut differences_map: Option<HashMap<u32, String>> = None;

                if let Some(encoding_obj) = font_dic.get("Encoding") {
                    let mut process_encoding_dict = |enc_dict: &HashMap<String, PdfObj>| {
                        encoding_name = enc_dict.get("BaseEncoding").and_then(|v| match v {
                            PdfObj::Name(s) => Some(s.clone()),
                            _ => None,
                        });
                        if let Some(PdfObj::Array(diff_arr)) = enc_dict.get("Differences") {
                            let mut diffs = HashMap::new();
                            let mut current_code = 0;
                            let mut is_code = true;
                            for item in diff_arr {
                                if is_code {
                                    if let PdfObj::Number(n) = item {
                                        current_code = *n as u32;
                                        is_code = false;
                                    }
                                } else {
                                    if let PdfObj::Name(name) = item {
                                        diffs.insert(current_code, name.clone());
                                        current_code += 1;
                                    } else {
                                        is_code = true;
                                        if let PdfObj::Number(n) = item {
                                            current_code = *n as u32;
                                            is_code = false;
                                        }
                                    }
                                }
                            }
                            if !diffs.is_empty() {
                                differences_map = Some(diffs);
                            }
                        }
                    };

                    match encoding_obj {
                        PdfObj::Name(s) => encoding_name = Some(s.clone()),
                        PdfObj::Dictionary(enc_dict) => process_encoding_dict(enc_dict),
                        PdfObj::Reference(eid) => {
                            if let Some(resolved_obj) = objects.get(eid) {
                                if let PdfObj::Dictionary(enc_dict) = resolved_obj {
                                    process_encoding_dict(enc_dict);
                                } else if let PdfObj::Name(s) = resolved_obj {
                                    encoding_name = Some(s.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }

                let mut to_uni_map: Option<HashMap<u32, String>> = None;
                if let Some(PdfObj::Reference(tu_ref)) = font_dic.get("ToUnicode") {
                    if let Some(PdfObj::Stream(tu_stream)) = objects.get(tu_ref) {
                        let cmap_bytes = if let Some(filter) = tu_stream.dict.get("Filter") {
                            let mut temp_vecs: Vec<Vec<u8>> = Vec::new();
                            handle_stream_filters(
                                filter,
                                &tu_stream.data,
                                decompress,
                                &mut temp_vecs,
                            )?;
                            if !temp_vecs.is_empty() {
                                temp_vecs.remove(0)
                            } else {
                                tu_stream.data.clone()
                            }
                        } else {
                            tu_stream.data.clone()
                        };
                        to_uni_map = Some(parse_cmap(&cmap_bytes));
                    }
                }

                let pdf_font = PdfFont {
                    base_name,
                    subtype,
                    encoding: encoding_name,
                    to_unicode_map: to_uni_map.map(|m| m.into_iter().collect()),
                    differences: differences_map,
                };
                fonts_map.insert(font_key.clone(), pdf_font);
            }
        }
    }
    Ok(fonts_map)
}

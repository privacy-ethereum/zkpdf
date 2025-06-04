use core::fmt;
use std::collections::HashMap;

#[derive(Debug)]
pub enum PdfError {
    ParseError(&'static str),
    DecompressionError,
}

impl fmt::Display for PdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdfError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            PdfError::DecompressionError => write!(f, "Decompression failed"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PdfFont {
    pub base_name: Option<String>,
    pub subtype: Option<String>,
    pub encoding: Option<String>,
    pub to_unicode_map: Option<HashMap<u32, String>>,
    pub differences: Option<HashMap<u32, String>>,
}

#[derive(Debug, Clone)]
pub struct PageContent {
    pub content_streams: Vec<Vec<u8>>,
    pub fonts: HashMap<String, PdfFont>,
    pub resources: HashMap<String, PdfObj>,
}

#[derive(Debug, Clone)]
pub enum PdfObj {
    Null,
    Boolean(bool),
    Number(f64),
    Name(String),
    String(Vec<u8>),
    Array(Vec<PdfObj>),
    Dictionary(HashMap<String, PdfObj>),
    Stream(PdfStream),
    Reference((u32, u16)),
}

#[derive(Debug, Clone)]
pub struct PdfStream {
    pub dict: HashMap<String, PdfObj>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Token {
    Number(f32),
    String(Vec<u8>),
    Name(String),
    Operator(String),
    Array(Vec<Token>),
    ArrayStart,
    ArrayEnd,
}

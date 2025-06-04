use miniz_oxide::inflate::decompress_to_vec_zlib;

pub fn decompress_to_utf8(compressed_data: &[u8]) -> Result<String, &'static str> {
    let decompressed =
        decompress_to_vec_zlib(compressed_data).map_err(|_| "Failed to decompress")?;

    String::from_utf8(decompressed).map_err(|_| "Decompressed data is not valid UTF-8")
}

#[cfg(test)]
mod tests {

    use crate::decompress_to_utf8;
    #[test]
    fn test_simple_decompress() {
        let compressed_data: &[u8] = &[
            120, 156, 11, 40, 202, 207, 79, 83, 0, 162, 0, 23, 55, 0, 27, 213, 3, 246,
        ];

        let result = decompress_to_utf8(compressed_data);

        match result {
            Ok(text) => {
                println!("Decompressed Text: {}", text);
                assert_eq!(text, "Proof of PDF");
            }
            Err(e) => panic!("Decompression failed: {}", e),
        }
    }
}

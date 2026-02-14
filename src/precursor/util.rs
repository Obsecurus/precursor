use base64::engine::{general_purpose::STANDARD, Engine};
use pcre2::bytes::{Regex, RegexBuilder};
use std::path::PathBuf;
use xxhash_rust::xxh3::xxh3_64;

pub fn xxh3_64_hex(input: Vec<u8>) -> (u64, String) {
    let hash = xxh3_64(&input);
    (hash, format!("{:x}", hash))
}

pub fn remove_wrapped_quotes(input: &str) -> &str {
    input
        .trim_start_matches(|c| c == '"' || c == '\'')
        .trim_end_matches(|c| c == '"' || c == '\'')
}

fn remove_wrapped_quotes_bytes(input: &[u8]) -> &[u8] {
    if input.len() < 2 {
        return input;
    }
    let first = input[0];
    let last = input[input.len() - 1];
    if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
        &input[1..input.len() - 1]
    } else {
        input
    }
}

pub fn get_payload(line: &str, input_mode: &str) -> Result<Vec<u8>, String> {
    let line_with_no_wrapped_quotes = remove_wrapped_quotes(line);
    match input_mode {
        "base64" => STANDARD
            .decode(line_with_no_wrapped_quotes)
            .map_err(|err| format!("invalid base64 payload: {}", err)),
        "string" => Ok(line_with_no_wrapped_quotes.as_bytes().to_vec()),
        "binary" => Ok(line.as_bytes().to_vec()),
        "hex" => hex::decode(line_with_no_wrapped_quotes)
            .map_err(|err| format!("invalid hex payload: {}", err)),
        _ => Err(format!("{} not a supported input mode.", input_mode)),
    }
}

pub fn get_payload_from_blob(blob: &[u8], input_mode: &str) -> Result<Vec<u8>, String> {
    match input_mode {
        "string" | "binary" => Ok(blob.to_vec()),
        "base64" | "hex" => {
            let normalized: Vec<u8> = blob
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            let normalized = remove_wrapped_quotes_bytes(normalized.as_slice());
            if input_mode == "base64" {
                STANDARD
                    .decode(normalized)
                    .map_err(|err| format!("invalid base64 payload: {}", err))
            } else {
                hex::decode(normalized).map_err(|err| format!("invalid hex payload: {}", err))
            }
        }
        _ => Err(format!("{} not a supported input mode.", input_mode)),
    }
}

pub fn format_size(size: i64) -> String {
    const KILOBYTE: i64 = 1024;
    const MEGABYTE: i64 = KILOBYTE * 1024;
    const GIGABYTE: i64 = MEGABYTE * 1024;
    const TERABYTE: i64 = GIGABYTE * 1024;

    if size < KILOBYTE {
        format!("{}B", size)
    } else if size < MEGABYTE {
        format!("{:.2}KB", (size as f64) / (KILOBYTE as f64))
    } else if size < GIGABYTE {
        format!("{:.2}MB", (size as f64) / (MEGABYTE as f64))
    } else if size < TERABYTE {
        format!("{:.2}GB", (size as f64) / (GIGABYTE as f64))
    } else {
        format!("{:.2}TB", (size as f64) / (TERABYTE as f64))
    }
}

pub fn read_patterns(pattern_file: Option<&PathBuf>) -> Result<Vec<String>, std::io::Error> {
    let mut patterns = Vec::new();
    if let Some(path) = pattern_file {
        let file_contents = std::fs::read_to_string(path)?;
        for line in file_contents.lines() {
            patterns.push(line.to_owned());
        }
    }
    Ok(patterns)
}

pub fn build_regex(pattern: &str) -> Result<Regex, Box<dyn std::error::Error>> {
    let re = RegexBuilder::new()
        // NOTE: We should only enable JIT if we're going to compile all patterns into one large PCRE2 statement
        // TODO: Pass CLI flags for certain REGEX settings down to the builder.
        .jit_if_available(false)
        .multi_line(true)
        .build(pattern)?;
    Ok(re)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempFileGuard {
        path: PathBuf,
    }

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn temp_file_path(stem: &str) -> (PathBuf, TempFileGuard) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("{}-{}-{}.txt", stem, std::process::id(), nanos));
        let guard = TempFileGuard {
            path: path.to_path_buf(),
        };
        (path, guard)
    }

    #[test]
    fn test_xxh3_64_hex() {
        let input = b"Hello, world!";
        let (hash, hex) = xxh3_64_hex(input.to_vec());
        assert_ne!(hash, 0);
        assert_eq!(hex, format!("{:x}", hash));
    }

    #[test]
    fn test_remove_wrapped_quotes() {
        assert_eq!(remove_wrapped_quotes("Hello"), "Hello");
        assert_eq!(remove_wrapped_quotes("\"Hello\""), "Hello");
        assert_eq!(remove_wrapped_quotes("'Hello'"), "Hello");
    }

    #[test]
    fn test_get_payload() {
        assert_eq!(
            get_payload("aGVsbG8=", "base64").expect("decode base64"),
            b"hello".to_vec()
        );
        assert_eq!(
            get_payload("hello", "string").expect("decode string"),
            b"hello".to_vec()
        );
        assert_eq!(
            get_payload("68656c6c6f", "hex").expect("decode hex"),
            b"hello".to_vec()
        );
        assert_eq!(
            get_payload("hello", "binary").expect("decode binary"),
            b"hello".to_vec()
        );

        let result = get_payload("hello", "invalid_mode");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_payload_from_blob() {
        assert_eq!(
            get_payload_from_blob(b"\"aGVs bG8=\"\n", "base64").expect("decode blob base64"),
            b"hello".to_vec()
        );
        assert_eq!(
            get_payload_from_blob(b"'68 65 6c 6c 6f'\r\n", "hex").expect("decode blob hex"),
            b"hello".to_vec()
        );
        let binary = vec![0x7f, b'E', b'L', b'F', 0x00, 0x01];
        assert_eq!(
            get_payload_from_blob(binary.as_slice(), "binary").expect("decode blob binary"),
            binary
        );
    }

    #[test]
    fn test_get_payload_from_blob_errors_are_decode_not_utf8() {
        let err = get_payload_from_blob(b"6865fg", "hex").expect_err("expect bad hex");
        assert!(err.contains("invalid hex payload"));
        assert!(!err.contains("UTF-8"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500B");
        assert_eq!(format_size(1023), "1023B");
        assert_eq!(format_size(1024), "1.00KB");
        assert_eq!(format_size(1536), "1.50KB");
        assert_eq!(format_size(1048576), "1.00MB");
        assert_eq!(format_size(1572864), "1.50MB");
        assert_eq!(format_size(1073741824), "1.00GB");
        assert_eq!(format_size(1610612736), "1.50GB");
        assert_eq!(format_size(1099511627776), "1.00TB");
        assert_eq!(format_size(1649267441664), "1.50TB");
    }

    #[test]
    fn test_read_patterns() {
        let (path, _guard) = temp_file_path("precursor-patterns");
        let mut file = File::create(&path).expect("create temp patterns file");
        write!(file, "pattern1\npattern2\n").expect("write patterns");

        let patterns = read_patterns(Some(&path)).expect("read patterns");
        assert_eq!(patterns, vec!["pattern1", "pattern2"]);
    }

    #[test]
    fn test_build_regex() {
        assert!(build_regex("\\d+").is_ok());
        assert!(build_regex("[InvalidRegex").is_err());
    }
}

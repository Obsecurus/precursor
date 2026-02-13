use crate::precursor::lzjd::{calculate_lzjd_hash, LzjdHash};
use crate::precursor::mrshv2::{calculate_mrshv2_hash, diff_mrshv2_hash, Mrshv2Hash};
use crate::precursor::tlsh::{calculate_tlsh_hash, TlshHashInstance};
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimilarityMode {
    Tlsh,
    Lzjd,
    Mrshv2,
    FbHash,
}

impl SimilarityMode {
    pub fn from_str(value: &str) -> Result<Self, SimilarityError> {
        match value {
            "tlsh" => Ok(Self::Tlsh),
            "lzjd" => Ok(Self::Lzjd),
            "mrshv2" => Ok(Self::Mrshv2),
            "fbhash" => Ok(Self::FbHash),
            _ => Err(SimilarityError::new(format!(
                "Unsupported similarity mode '{}'",
                value
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tlsh => "tlsh",
            Self::Lzjd => "lzjd",
            Self::Mrshv2 => "mrshv2",
            Self::FbHash => "fbhash",
        }
    }
}

pub enum SimilarityHash {
    Tlsh(TlshHashInstance),
    Lzjd(LzjdHash),
    Mrshv2(Mrshv2Hash),
}

impl SimilarityHash {
    pub fn as_string(&self) -> Result<String, SimilarityError> {
        match self {
            SimilarityHash::Tlsh(hash) => String::from_utf8(hash.hash().to_ascii_lowercase())
                .map_err(|err| SimilarityError::new(format!("Invalid TLSH hash UTF-8: {}", err))),
            SimilarityHash::Lzjd(hash) => Ok(hash.as_string()),
            SimilarityHash::Mrshv2(hash) => Ok(hash.as_string().to_string()),
        }
    }
}

#[derive(Debug)]
pub struct SimilarityError {
    message: String,
}

impl SimilarityError {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for SimilarityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for SimilarityError {}

pub fn calculate_similarity_hash(
    payload: &[u8],
    mode: &SimilarityMode,
    tlsh_algorithm: &str,
) -> Result<SimilarityHash, SimilarityError> {
    match mode {
        SimilarityMode::Tlsh => calculate_tlsh_hash(payload, &tlsh_algorithm.to_string())
            .map(SimilarityHash::Tlsh)
            .map_err(|err| SimilarityError::new(err.to_string())),
        SimilarityMode::Lzjd => calculate_lzjd_hash(payload)
            .map(SimilarityHash::Lzjd)
            .map_err(SimilarityError::new),
        SimilarityMode::Mrshv2 => calculate_mrshv2_hash(payload)
            .map(SimilarityHash::Mrshv2)
            .map_err(SimilarityError::new),
        SimilarityMode::FbHash => Err(SimilarityError::new(
            "FBHash similarity mode is scaffolded but not implemented yet".to_string(),
        )),
    }
}

pub fn diff_similarity_hash(
    left: &SimilarityHash,
    right: &SimilarityHash,
    include_file_length: bool,
) -> Result<i32, SimilarityError> {
    match (left, right) {
        (SimilarityHash::Tlsh(left_hash), SimilarityHash::Tlsh(right_hash)) => left_hash
            .diff(right_hash, include_file_length)
            .ok_or_else(|| {
                SimilarityError::new("Incompatible TLSH hash algorithm types".to_string())
            }),
        (SimilarityHash::Lzjd(left_hash), SimilarityHash::Lzjd(right_hash)) => {
            Ok(left_hash.diff(right_hash, include_file_length))
        }
        (SimilarityHash::Mrshv2(left_hash), SimilarityHash::Mrshv2(right_hash)) => {
            diff_mrshv2_hash(left_hash, right_hash, include_file_length)
                .map_err(SimilarityError::new)
        }
        _ => Err(SimilarityError::new(
            "Incompatible similarity hash algorithm types".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_similarity_mode_lzjd_roundtrip() {
        let mode = SimilarityMode::from_str("lzjd").expect("expected mode");
        assert_eq!(mode, SimilarityMode::Lzjd);
        assert_eq!(mode.as_str(), "lzjd");
    }

    #[test]
    fn test_calculate_and_diff_lzjd() {
        let payload = b"GET /index HTTP/1.1\r\nHost: example.org\r\n";
        let left = calculate_similarity_hash(payload, &SimilarityMode::Lzjd, "48_1")
            .expect("expected left hash");
        let right = calculate_similarity_hash(payload, &SimilarityMode::Lzjd, "48_1")
            .expect("expected right hash");
        let rendered = left.as_string().expect("expected string form");
        assert!(rendered.starts_with("lzjd:"));
        let distance = diff_similarity_hash(&left, &right, false).expect("expected distance");
        assert_eq!(distance, 0);
    }

    #[test]
    fn test_similarity_mode_mrshv2_roundtrip() {
        let mode = SimilarityMode::from_str("mrshv2").expect("expected mode");
        assert_eq!(mode, SimilarityMode::Mrshv2);
        assert_eq!(mode.as_str(), "mrshv2");
    }
}

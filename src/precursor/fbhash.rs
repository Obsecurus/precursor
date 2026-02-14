use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
use xxhash_rust::xxh3::xxh3_64;

const FBHASH_WINDOW_SIZE: usize = 7;
const FBHASH_FINGERPRINT_FEATURES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FbHash {
    features: Vec<(u64, u32)>,
    payload_len: usize,
    digest: String,
}

impl FbHash {
    pub fn as_string(&self) -> &str {
        self.digest.as_str()
    }

    pub fn diff(&self, right: &Self, include_file_length: bool) -> i32 {
        let mut left_idx = 0usize;
        let mut right_idx = 0usize;
        let mut dot_product = 0.0f64;
        let mut norm_left = 0.0f64;
        let mut norm_right = 0.0f64;

        while left_idx < self.features.len() && right_idx < right.features.len() {
            let (left_hash, left_tf) = self.features[left_idx];
            let (right_hash, right_tf) = right.features[right_idx];
            match left_hash.cmp(&right_hash) {
                Ordering::Equal => {
                    let left_weight = feature_weight(left_tf, 2);
                    let right_weight = feature_weight(right_tf, 2);
                    dot_product += left_weight * right_weight;
                    norm_left += left_weight * left_weight;
                    norm_right += right_weight * right_weight;
                    left_idx += 1;
                    right_idx += 1;
                }
                Ordering::Less => {
                    let left_weight = feature_weight(left_tf, 1);
                    norm_left += left_weight * left_weight;
                    left_idx += 1;
                }
                Ordering::Greater => {
                    let right_weight = feature_weight(right_tf, 1);
                    norm_right += right_weight * right_weight;
                    right_idx += 1;
                }
            }
        }

        while left_idx < self.features.len() {
            let (_, left_tf) = self.features[left_idx];
            let left_weight = feature_weight(left_tf, 1);
            norm_left += left_weight * left_weight;
            left_idx += 1;
        }
        while right_idx < right.features.len() {
            let (_, right_tf) = right.features[right_idx];
            let right_weight = feature_weight(right_tf, 1);
            norm_right += right_weight * right_weight;
            right_idx += 1;
        }

        let cosine_similarity = if norm_left == 0.0 || norm_right == 0.0 {
            0.0
        } else {
            dot_product / (norm_left.sqrt() * norm_right.sqrt())
        };
        let mut distance = ((1.0 - cosine_similarity.clamp(0.0, 1.0)) * 100.0).round() as i32;

        if include_file_length {
            let max_len = self.payload_len.max(right.payload_len) as f64;
            if max_len > 0.0 {
                let len_delta = self.payload_len.abs_diff(right.payload_len) as f64;
                let len_penalty = ((len_delta / max_len) * 10.0).round() as i32;
                distance = (distance + len_penalty).clamp(0, 100);
            }
        }

        distance.clamp(0, 100)
    }
}

pub fn calculate_fbhash(payload: &[u8]) -> Result<FbHash, String> {
    if payload.is_empty() {
        return Err("FBHash requires a non-empty payload".to_string());
    }

    let mut frequencies: HashMap<u64, u32> = HashMap::new();
    let mut chunk_count = 0usize;

    if payload.len() < FBHASH_WINDOW_SIZE {
        let hash = xxh3_64(payload);
        frequencies.insert(hash, 1);
        chunk_count = 1;
    } else {
        for chunk in payload.windows(FBHASH_WINDOW_SIZE) {
            let hash = xxh3_64(chunk);
            let entry = frequencies.entry(hash).or_insert(0);
            *entry += 1;
            chunk_count += 1;
        }
    }

    if frequencies.is_empty() {
        return Err("FBHash failed to extract any chunk features".to_string());
    }

    let mut features: Vec<(u64, u32)> = frequencies.into_iter().collect();
    features.sort_unstable_by_key(|(feature_hash, _)| *feature_hash);

    let digest = render_digest(features.as_slice(), payload.len(), chunk_count);
    Ok(FbHash {
        features,
        payload_len: payload.len(),
        digest,
    })
}

fn feature_weight(term_frequency: u32, document_frequency: u32) -> f64 {
    // FBHash-inspired weighting: log-scaled TF with a local two-document IDF proxy.
    let tf = 1.0 + (term_frequency as f64).ln();
    let idf = (1.0 + (2.0 / document_frequency as f64)).ln();
    tf * idf
}

fn render_digest(features: &[(u64, u32)], payload_len: usize, chunk_count: usize) -> String {
    let mut ranked = features.to_vec();
    ranked.sort_unstable_by(|(left_hash, left_tf), (right_hash, right_tf)| {
        right_tf
            .cmp(left_tf)
            .then_with(|| left_hash.cmp(right_hash))
    });
    ranked.truncate(FBHASH_FINGERPRINT_FEATURES);

    let mut digest_bytes = Vec::with_capacity((ranked.len() * 12) + 16);
    digest_bytes.extend_from_slice(&(payload_len as u64).to_be_bytes());
    digest_bytes.extend_from_slice(&(chunk_count as u64).to_be_bytes());
    for (feature_hash, term_frequency) in ranked {
        digest_bytes.extend_from_slice(&feature_hash.to_be_bytes());
        digest_bytes.extend_from_slice(&term_frequency.to_be_bytes());
    }
    let digest = Sha256::digest(digest_bytes.as_slice());
    let short_fingerprint = hex::encode(&digest[..16]);
    format!("fbhash:{}:{}", features.len(), short_fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_fbhash_prefix() {
        let hash = calculate_fbhash(b"GET / HTTP/1.1\r\nHost: example.org\r\n")
            .expect("expected fbhash hash");
        assert!(hash.as_string().starts_with("fbhash:"));
    }

    #[test]
    fn test_diff_identical_payloads_is_zero() {
        let left = calculate_fbhash(b"AAAAABBBBBCCCCCDDDD").expect("expected left hash");
        let right = calculate_fbhash(b"AAAAABBBBBCCCCCDDDD").expect("expected right hash");
        assert_eq!(left.diff(&right, false), 0);
    }

    #[test]
    fn test_diff_changes_with_different_payloads() {
        let left = calculate_fbhash(b"AAAAABBBBBCCCCCDDDD").expect("expected left hash");
        let right =
            calculate_fbhash(b"\x7fELF\x02\x01\x01\x00\xAA\xBB\xCC\xDD").expect("expected right");
        assert!(left.diff(&right, false) > 0);
    }

    #[test]
    fn test_short_payload_supported() {
        let hash = calculate_fbhash(b"abc").expect("expected short hash");
        assert!(hash.as_string().starts_with("fbhash:"));
    }
}

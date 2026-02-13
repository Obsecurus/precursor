use sha2::{Digest, Sha256};
use std::collections::HashSet;

const LZJD_SKETCH_SIZE: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LzjdHash {
    sketch: Vec<u64>,
    payload_len: usize,
}

impl LzjdHash {
    pub fn as_string(&self) -> String {
        let mut sketch_bytes = Vec::with_capacity((self.sketch.len() + 1) * 8);
        sketch_bytes.extend_from_slice(&(self.payload_len as u64).to_be_bytes());
        for bucket in self.sketch.iter() {
            sketch_bytes.extend_from_slice(&bucket.to_be_bytes());
        }
        let digest = Sha256::digest(sketch_bytes.as_slice());
        let short_fingerprint = hex::encode(&digest[..16]);
        format!("lzjd:{}:{}", self.sketch.len(), short_fingerprint)
    }

    pub fn diff(&self, right: &Self, include_file_length: bool) -> i32 {
        let jaccard_similarity =
            jaccard_similarity(self.sketch.as_slice(), right.sketch.as_slice());
        let mut distance = ((1.0 - jaccard_similarity) * 100.0).round() as i32;

        if include_file_length {
            let max_len = self.payload_len.max(right.payload_len) as f64;
            if max_len > 0.0 {
                let len_delta = self.payload_len.abs_diff(right.payload_len) as f64;
                let len_penalty = ((len_delta / max_len) * 10.0).round() as i32;
                distance = (distance + len_penalty).clamp(0, 100);
            }
        }

        distance
    }
}

pub fn calculate_lzjd_hash(payload: &[u8]) -> Result<LzjdHash, String> {
    if payload.is_empty() {
        return Err("LZJD hash requires a non-empty payload".to_string());
    }

    let phrases = lz78_phrases(payload);
    if phrases.is_empty() {
        return Err("LZJD hash produced an empty phrase set".to_string());
    }

    let mut sketch: Vec<u64> = phrases
        .into_iter()
        .map(|phrase| hash_phrase_to_bucket(phrase.as_slice()))
        .collect();
    sketch.sort_unstable();
    sketch.dedup();
    sketch.truncate(LZJD_SKETCH_SIZE);

    if sketch.is_empty() {
        return Err("LZJD hash produced an empty sketch".to_string());
    }

    Ok(LzjdHash {
        sketch,
        payload_len: payload.len(),
    })
}

fn lz78_phrases(payload: &[u8]) -> HashSet<Vec<u8>> {
    let mut dictionary: HashSet<Vec<u8>> = HashSet::new();
    let mut start = 0usize;

    while start < payload.len() {
        let mut end = start + 1;
        while end <= payload.len() && dictionary.contains(&payload[start..end]) {
            end += 1;
        }

        if end <= payload.len() {
            dictionary.insert(payload[start..end].to_vec());
            start = end;
        } else {
            dictionary.insert(payload[start..payload.len()].to_vec());
            break;
        }
    }

    dictionary
}

fn hash_phrase_to_bucket(phrase: &[u8]) -> u64 {
    let digest = Sha256::digest(phrase);
    let mut bucket = [0u8; 8];
    bucket.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bucket)
}

fn jaccard_similarity(left: &[u64], right: &[u64]) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }

    let mut i = 0usize;
    let mut j = 0usize;
    let mut intersection = 0usize;

    while i < left.len() && j < right.len() {
        match left[i].cmp(&right[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                intersection += 1;
                i += 1;
                j += 1;
            }
        }
    }

    let union = left.len() + right.len() - intersection;
    if union == 0 {
        return 1.0;
    }
    intersection as f64 / union as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_lzjd_hash_returns_stable_prefix() {
        let hash = calculate_lzjd_hash(b"GET / HTTP/1.1\r\nHost: example.org\r\n")
            .expect("expected lzjd hash");
        let rendered = hash.as_string();
        assert!(rendered.starts_with("lzjd:"));
    }

    #[test]
    fn test_diff_identical_payloads_is_zero() {
        let left = calculate_lzjd_hash(b"AAAAABBBBBCCCCCDDDD").expect("expected left hash");
        let right = calculate_lzjd_hash(b"AAAAABBBBBCCCCCDDDD").expect("expected right hash");
        assert_eq!(left.diff(&right, false), 0);
    }

    #[test]
    fn test_diff_changes_with_different_payloads() {
        let left = calculate_lzjd_hash(b"AAAAABBBBBCCCCCDDDD").expect("expected left hash");
        let right = calculate_lzjd_hash(b"\x7fELF\x02\x01\x01\x00\xAA\xBB\xCC\xDD")
            .expect("expected right hash");
        assert!(left.diff(&right, false) > 0);
    }

    #[test]
    fn test_diff_with_length_penalty() {
        let short = calculate_lzjd_hash(b"GET /short HTTP/1.1").expect("expected short hash");
        let long = calculate_lzjd_hash(
            b"GET /a/very/long/path HTTP/1.1\r\nHost: example.org\r\nUser-Agent: precursor\r\n",
        )
        .expect("expected long hash");
        assert!(short.diff(&long, true) >= short.diff(&long, false));
    }
}

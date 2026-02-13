use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct ProtocolCandidate {
    pub protocol: String,
    pub score: f64,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ProtocolInference {
    pub label: String,
    pub confidence: f64,
    pub abstained: bool,
    pub candidates: Vec<ProtocolCandidate>,
}

fn shannon_entropy(payload: &[u8]) -> f64 {
    if payload.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in payload {
        counts[*byte as usize] += 1;
    }
    let payload_len = payload.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / payload_len;
        entropy -= probability * probability.log2();
    }
    entropy
}

fn printable_ratio(payload: &[u8]) -> f64 {
    if payload.is_empty() {
        return 0.0;
    }
    let printable = payload
        .iter()
        .filter(|byte| matches!(**byte, b'\n' | b'\r' | b'\t' | 0x20..=0x7e))
        .count() as f64;
    printable / payload.len() as f64
}

fn has_magic(payload: &[u8], magic: &[u8]) -> bool {
    payload.starts_with(magic)
}

fn add_score(
    scores: &mut HashMap<String, (f64, Vec<String>)>,
    protocol: &str,
    score: f64,
    evidence: &str,
) {
    let entry = scores
        .entry(protocol.to_string())
        .or_insert((0.0, Vec::<String>::new()));
    entry.0 += score;
    entry.1.push(evidence.to_string());
}

fn lowercase_payload(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload).to_ascii_lowercase()
}

pub fn infer_protocol_candidates(
    payload: &[u8],
    tags: &[String],
    neighbor_count: usize,
    top_k: usize,
    abstain_threshold: f64,
) -> ProtocolInference {
    let mut scores: HashMap<String, (f64, Vec<String>)> = HashMap::new();
    let lower_payload = lowercase_payload(payload);
    let entropy = shannon_entropy(payload);
    let printable = printable_ratio(payload);
    let payload_len = payload.len();

    if lower_payload.starts_with("get ")
        || lower_payload.starts_with("post ")
        || lower_payload.starts_with("head ")
        || lower_payload.starts_with("put ")
        || lower_payload.starts_with("delete ")
        || lower_payload.contains(" http/1.")
        || lower_payload.contains("host:")
    {
        add_score(&mut scores, "http", 0.85, "matched HTTP request/headers");
    }

    if payload_len >= 3 && payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04 {
        add_score(
            &mut scores,
            "tls",
            0.9,
            "matched TLS handshake prefix 16 03 xx",
        );
    }

    if lower_payload.starts_with("ssh-") {
        add_score(
            &mut scores,
            "ssh",
            0.95,
            "matched SSH identification banner",
        );
    }

    if lower_payload.starts_with("ehlo ")
        || lower_payload.starts_with("helo ")
        || lower_payload.starts_with("mail from:")
        || lower_payload.starts_with("rcpt to:")
        || lower_payload.starts_with("220 ")
        || lower_payload.starts_with("250 ")
    {
        add_score(
            &mut scores,
            "smtp",
            0.78,
            "matched SMTP command/response markers",
        );
    }

    if lower_payload.starts_with("user ")
        || lower_payload.starts_with("pass ")
        || lower_payload.starts_with("+ok")
        || lower_payload.starts_with("-err")
    {
        add_score(
            &mut scores,
            "pop3_or_ftp",
            0.66,
            "matched POP3/FTP style tokens",
        );
    }

    if lower_payload.starts_with("{") && lower_payload.contains(':') && printable > 0.95 {
        add_score(
            &mut scores,
            "json_application",
            0.52,
            "high-printable JSON-like payload shape",
        );
    }

    if has_magic(payload, b"\x7fELF") {
        add_score(&mut scores, "firmware_binary", 0.98, "ELF magic header");
    }
    if has_magic(payload, b"MZ") {
        add_score(&mut scores, "firmware_binary", 0.85, "PE/COFF MZ header");
    }
    if has_magic(payload, b"\x1f\x8b") {
        add_score(&mut scores, "compressed_binary", 0.88, "gzip magic header");
    }
    if has_magic(payload, b"PK\x03\x04") {
        add_score(&mut scores, "compressed_binary", 0.8, "zip magic header");
    }
    if payload_len >= 4 && payload[0..4] == [0x27, 0x05, 0x19, 0x56] {
        add_score(
            &mut scores,
            "firmware_binary",
            0.86,
            "uImage magic header (0x27051956)",
        );
    }

    if printable < 0.35 && entropy > 6.2 {
        add_score(
            &mut scores,
            "opaque_binary_stream",
            0.6,
            "low-printable/high-entropy binary characteristics",
        );
    }

    if lower_payload.contains("/bin/sh")
        || lower_payload.starts_with("wget ")
        || lower_payload.starts_with("curl ")
        || lower_payload.starts_with("busybox ")
        || lower_payload.starts_with("chmod ")
        || lower_payload.starts_with("powershell ")
    {
        add_score(
            &mut scores,
            "shell_command",
            0.72,
            "matched command execution markers",
        );
    }

    let dot_count = lower_payload.matches('.').count();
    if printable > 0.9 && dot_count >= 2 && !lower_payload.contains(' ') {
        add_score(
            &mut scores,
            "dns_or_domain_payload",
            0.44,
            "domain-like token shape",
        );
    }

    for tag in tags {
        let tag_lower = tag.to_ascii_lowercase();
        if tag_lower.contains("http") {
            add_score(&mut scores, "http", 0.2, "tag evidence: http");
        }
        if tag_lower.contains("tls") || tag_lower.contains("ssl") {
            add_score(&mut scores, "tls", 0.2, "tag evidence: tls/ssl");
        }
        if tag_lower.contains("dns") {
            add_score(
                &mut scores,
                "dns_or_domain_payload",
                0.2,
                "tag evidence: dns",
            );
        }
        if tag_lower.contains("ssh") {
            add_score(&mut scores, "ssh", 0.2, "tag evidence: ssh");
        }
        if tag_lower.contains("firmware") || tag_lower.contains("elf") {
            add_score(
                &mut scores,
                "firmware_binary",
                0.2,
                "tag evidence: firmware/elf",
            );
        }
    }

    let neighbor_boost = (neighbor_count as f64).ln_1p() * 0.08;
    if neighbor_boost > 0.0 {
        for (_protocol, (score, evidence)) in scores.iter_mut() {
            *score += neighbor_boost.min(0.25);
            evidence.push(format!(
                "similarity cluster boost from {} neighbors",
                neighbor_count
            ));
        }
    }

    let mut candidates: Vec<ProtocolCandidate> = scores
        .into_iter()
        .map(|(protocol, (score, evidence))| ProtocolCandidate {
            protocol,
            score: score.clamp(0.0, 0.99),
            evidence,
        })
        .collect();

    candidates.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if candidates.is_empty() {
        return ProtocolInference {
            label: "unknown".to_string(),
            confidence: 0.0,
            abstained: true,
            candidates: vec![ProtocolCandidate {
                protocol: "unknown".to_string(),
                score: 0.0,
                evidence: vec!["no protocol heuristics matched".to_string()],
            }],
        };
    }

    let top = candidates[0].clone();
    let abstained = top.score < abstain_threshold.clamp(0.0, 1.0);
    let label = if abstained {
        "unknown".to_string()
    } else {
        top.protocol.clone()
    };

    ProtocolInference {
        label,
        confidence: top.score,
        abstained,
        candidates: candidates.into_iter().take(top_k.max(1)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_candidate() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n";
        let inference = infer_protocol_candidates(payload, &[], 0, 3, 0.6);
        assert_eq!(inference.label, "http");
        assert!(!inference.abstained);
    }

    #[test]
    fn test_tls_candidate() {
        let payload = vec![0x16, 0x03, 0x03, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b];
        let inference = infer_protocol_candidates(&payload, &[], 0, 3, 0.6);
        assert_eq!(inference.label, "tls");
        assert!(!inference.abstained);
    }

    #[test]
    fn test_firmware_magic_candidate() {
        let payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let inference = infer_protocol_candidates(payload, &[], 0, 3, 0.6);
        assert_eq!(inference.label, "firmware_binary");
    }

    #[test]
    fn test_abstain_on_ambiguous_payload() {
        let payload = b"abc";
        let inference = infer_protocol_candidates(payload, &[], 0, 3, 0.8);
        assert_eq!(inference.label, "unknown");
        assert!(inference.abstained);
    }

    #[test]
    fn test_neighbor_boost_changes_confidence() {
        let payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let without_neighbors = infer_protocol_candidates(payload, &[], 0, 3, 0.95);
        let with_neighbors = infer_protocol_candidates(payload, &[], 20, 3, 0.95);
        assert!(with_neighbors.confidence > without_neighbors.confidence);
    }
}

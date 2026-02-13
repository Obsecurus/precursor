use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run_precursor(args: &[&str], stdin_payload: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_precursor"));
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn precursor");
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(stdin_payload.as_bytes())
            .expect("failed to write stdin");
    }
    let output = child.wait_with_output().expect("failed to wait on process");
    assert!(
        output.status.success(),
        "process failed with status {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn parse_ndjson(stdout: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|err| panic!("invalid JSON line {:?}: {}", line, err))
        })
        .collect()
}

#[test]
fn single_packet_emits_protocol_fields() {
    let output = run_precursor(
        &["(?<http_get>GET)", "-m", "string", "-P"],
        "GET /index.html HTTP/1.1 Host: example.org User-Agent: precursor-test\n",
    );

    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 1);
    let report = &reports[0];
    assert!(report.get("protocol_label").is_some());
    assert!(report.get("protocol_confidence").is_some());
    assert!(report.get("protocol_abstained").is_some());
    assert!(report
        .get("protocol_candidates")
        .and_then(Value::as_array)
        .map(|candidates| !candidates.is_empty())
        .unwrap_or(false));
}

#[test]
fn protocol_hints_include_inference_context() {
    let line_one =
        "GET /one HTTP/1.1 Host: example.org User-Agent: precursor-long-test-agent-aaaaaaaaaa";
    let line_two =
        "GET /two HTTP/1.1 Host: example.org User-Agent: precursor-long-test-agent-bbbbbbbbbb";
    let stdin_payload = format!("{}\n{}\n", line_one, line_two);

    let output = run_precursor(
        &[
            "(?<http_get>GET)",
            "-m",
            "string",
            "-P",
            "-t",
            "-d",
            "--protocol-hints",
            "--protocol-hints-limit",
            "5",
        ],
        &stdin_payload,
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let start = stderr
        .find('{')
        .unwrap_or_else(|| panic!("expected protocol hint JSON in stderr, got: {}", stderr));
    let end = stderr
        .rfind('}')
        .unwrap_or_else(|| panic!("expected protocol hint JSON in stderr, got: {}", stderr));
    let hints: Value = serde_json::from_str(&stderr[start..=end])
        .unwrap_or_else(|err| panic!("unable to parse hint JSON: {} in {}", err, stderr));

    assert!(hints.get("---PRECURSOR_PROTOCOL_HINTS---").is_some());
    assert!(hints.get("Candidates").and_then(Value::as_array).is_some());
}

#[test]
fn input_blob_mode_supports_multiline_patterns() {
    let pattern = "(?<multi>GET /blob HTTP/1\\.1\\nHost: blob\\.example)";
    let blob_payload = "GET /blob HTTP/1.1\nHost: blob.example\n";

    let line_output = run_precursor(&[pattern, "-m", "string"], blob_payload);
    let line_reports = parse_ndjson(&line_output.stdout);
    assert_eq!(
        line_reports.len(),
        0,
        "line mode should not match cross-line pattern"
    );

    let blob_output = run_precursor(&[pattern, "-m", "string", "-z"], blob_payload);
    let blob_reports = parse_ndjson(&blob_output.stdout);
    assert_eq!(blob_reports.len(), 1);
    assert!(blob_reports[0]
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| tags.iter().any(|tag| tag.as_str() == Some("multi")))
        .unwrap_or(false));
}

#[test]
fn lzjd_similarity_mode_emits_backend_hashes() {
    let line_one =
        "GET /one HTTP/1.1 Host: example.org User-Agent: precursor-long-test-agent-aaaaaaaaaa";
    let line_two =
        "GET /two HTTP/1.1 Host: example.org User-Agent: precursor-long-test-agent-bbbbbbbbbb";
    let stdin_payload = format!("{}\n{}\n", line_one, line_two);

    let output = run_precursor(
        &[
            "(?<http_get>GET)",
            "-m",
            "string",
            "-t",
            "-d",
            "--similarity-mode",
            "lzjd",
            "-x",
            "100",
        ],
        &stdin_payload,
    );

    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 2);

    assert!(reports.iter().all(|report| {
        report
            .get("similarity_hash")
            .and_then(Value::as_str)
            .map(|value| value.starts_with("lzjd:"))
            .unwrap_or(false)
    }));

    assert!(reports.iter().any(|report| {
        report
            .get("tlsh_similarities")
            .and_then(Value::as_object)
            .map(|obj| !obj.is_empty())
            .unwrap_or(false)
    }));
}

#[cfg(feature = "similarity-mrshv2")]
#[test]
fn mrshv2_similarity_mode_emits_backend_hashes() {
    let line_one =
        "GET /one HTTP/1.1 Host: example.org User-Agent: precursor-long-test-agent-aaaaaaaaaa";
    let line_two =
        "GET /two HTTP/1.1 Host: example.org User-Agent: precursor-long-test-agent-bbbbbbbbbb";
    let stdin_payload = format!("{}\n{}\n", line_one, line_two);

    let output = run_precursor(
        &[
            "(?<http_get>GET)",
            "-m",
            "string",
            "-t",
            "-d",
            "--similarity-mode",
            "mrshv2",
            "-x",
            "100",
        ],
        &stdin_payload,
    );

    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 2);

    assert!(reports.iter().all(|report| {
        report
            .get("similarity_hash")
            .and_then(Value::as_str)
            .map(|value| value.starts_with("mrshv2:"))
            .unwrap_or(false)
    }));
}

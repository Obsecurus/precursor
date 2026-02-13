use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
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

fn scenario_paths() -> (PathBuf, PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples/scenarios");
    let pre = root.join("pre-protocol-packet-triage");
    let firmware = root.join("firmware-fragment-triage");
    let modbus = root.join("ics-modbus-single-packet");
    (pre, firmware, modbus)
}

#[test]
fn pre_protocol_packet_scenario_emits_clusterable_hashes() {
    let (pre, _, _) = scenario_paths();
    let pattern_file = pre.join("patterns.pcre");
    let payloads = std::fs::read_to_string(pre.join("payloads.b64")).expect("read payloads");

    let output = run_precursor(
        &[
            "-p",
            pattern_file.to_str().expect("pattern path utf8"),
            "-m",
            "base64",
            "-t",
            "-d",
            "-x",
            "100",
            "-P",
            "--similarity-mode",
            "lzjd",
        ],
        payloads.as_str(),
    );

    let reports = parse_ndjson(&output.stdout);
    assert!(
        reports.len() >= 4,
        "expected at least 4 reports, got {}",
        reports.len()
    );
    assert!(reports.iter().all(|report| {
        report
            .get("similarity_hash")
            .and_then(Value::as_str)
            .map(|value| value.starts_with("lzjd:"))
            .unwrap_or(false)
    }));
}

#[test]
fn firmware_fragment_scenario_hits_firmware_inference() {
    let (_, firmware, _) = scenario_paths();
    let pattern_file = firmware.join("patterns.pcre");
    let payloads = std::fs::read_to_string(firmware.join("payloads.hex")).expect("read payloads");

    let output = run_precursor(
        &[
            "-p",
            pattern_file.to_str().expect("pattern path utf8"),
            "-m",
            "hex",
            "-t",
            "-P",
            "--similarity-mode",
            "lzjd",
        ],
        payloads.as_str(),
    );

    let reports = parse_ndjson(&output.stdout);
    assert!(
        reports.iter().any(|report| {
            report
                .get("protocol_label")
                .and_then(Value::as_str)
                .map(|value| value == "firmware_binary")
                .unwrap_or(false)
        }),
        "expected at least one firmware_binary protocol label"
    );
}

#[test]
fn modbus_scenario_emits_protocol_hints() {
    let (_, _, modbus) = scenario_paths();
    let pattern_file = modbus.join("patterns.pcre");
    let payloads = std::fs::read_to_string(modbus.join("payloads.hex")).expect("read payloads");

    let output = run_precursor(
        &[
            "-p",
            pattern_file.to_str().expect("pattern path utf8"),
            "-m",
            "hex",
            "-t",
            "-d",
            "-x",
            "100",
            "-P",
            "--protocol-hints",
            "--protocol-hints-limit",
            "5",
            "--similarity-mode",
            "lzjd",
        ],
        payloads.as_str(),
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
    assert!(hints
        .get("Candidates")
        .and_then(Value::as_array)
        .map(|candidates| !candidates.is_empty())
        .unwrap_or(false));
}

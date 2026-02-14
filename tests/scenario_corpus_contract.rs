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

fn scenario_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples/scenarios")
}

#[test]
fn pre_protocol_packet_scenario_emits_clusterable_hashes() {
    let pre = scenario_root().join("pre-protocol-packet-triage");
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
    let firmware = scenario_root().join("firmware-fragment-triage");
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
    let modbus = scenario_root().join("ics-modbus-single-packet");
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

#[test]
fn log4shell_pcap_derived_scenario_emits_http_and_jndi_tags() {
    let scenario = scenario_root().join("public-log4shell-pcap-derived");
    let pattern_file = scenario.join("patterns.pcre");
    let payloads =
        std::fs::read_to_string(scenario.join("payloads.string")).expect("read payloads");

    let output = run_precursor(
        &[
            "-p",
            pattern_file.to_str().expect("pattern path utf8"),
            "-m",
            "string",
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
        reports.len() >= 6,
        "expected at least 6 reports, got {}",
        reports.len()
    );
    assert!(reports.iter().all(|report| {
        report
            .get("protocol_label")
            .and_then(Value::as_str)
            .map(|value| value == "http")
            .unwrap_or(false)
    }));
    assert!(reports.iter().all(|report| {
        report
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .any(|tag| tag.as_str() == Some("jndi_expression"))
            })
            .unwrap_or(false)
    }));
}

#[test]
fn sigma_shell_scenario_generates_matches_from_sigma_yaml() {
    let scenario = scenario_root().join("sigma-linux-shell-command-triage");
    let sigma_rule = scenario.join("sigma_rule.yml");
    let payloads = std::fs::read_to_string(scenario.join("payloads.log")).expect("read payloads");

    let output = run_precursor(
        &[
            "--sigma-rule",
            sigma_rule.to_str().expect("sigma path utf8"),
            "-m",
            "string",
            "-t",
            "-d",
            "--similarity-mode",
            "lzjd",
        ],
        payloads.as_str(),
    );

    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 5);
    assert!(reports.iter().any(|report| {
        report
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter().any(|tag| {
                    tag.as_str()
                        .map(|value| value.starts_with("sigma_"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }));
    assert!(reports.iter().all(|report| {
        report
            .get("sigma_rule_matches")
            .and_then(Value::as_array)
            .map(|rules| !rules.is_empty())
            .unwrap_or(false)
    }));
}

#[test]
fn zeek_dns_log_scenario_extracts_query_field() {
    let scenario = scenario_root().join("public-zeek-dns-log-triage");
    let pattern_file = scenario.join("patterns.pcre");
    let payloads = std::fs::read_to_string(scenario.join("payloads.jsonl")).expect("read payloads");

    let output = run_precursor(
        &[
            "-p",
            pattern_file.to_str().expect("pattern path utf8"),
            "-m",
            "string",
            "-j",
            ".query",
            "-t",
            "-d",
            "--similarity-mode",
            "lzjd",
        ],
        payloads.as_str(),
    );

    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 4);
    assert!(reports.iter().any(|report| {
        report
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .any(|tag| tag.as_str() == Some("possible_c2_domain"))
            })
            .unwrap_or(false)
    }));
}

#[test]
fn foxit_log4shell_pcap_scenario_emits_fbhash_and_jndi_tags() {
    let scenario = scenario_root().join("public-log4shell-foxit-pcap");
    let pattern_file = scenario.join("patterns.pcre");
    let payloads =
        std::fs::read_to_string(scenario.join("payloads.string")).expect("read payloads");

    let output = run_precursor(
        &[
            "-p",
            pattern_file.to_str().expect("pattern path utf8"),
            "-m",
            "string",
            "-t",
            "-d",
            "--similarity-mode",
            "fbhash",
            "-P",
        ],
        payloads.as_str(),
    );

    let reports = parse_ndjson(&output.stdout);
    assert!(
        reports.len() >= 10,
        "expected at least 10 reports, got {}",
        reports.len()
    );
    assert!(reports.iter().all(|report| {
        report
            .get("similarity_hash")
            .and_then(Value::as_str)
            .map(|value| value.starts_with("fbhash:"))
            .unwrap_or(false)
    }));
    assert!(reports.iter().any(|report| {
        report
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .any(|tag| tag.as_str() == Some("urlencoded_jndi"))
            })
            .unwrap_or(false)
    }));
}

#[test]
fn public_firmware_binwalk_scenario_tags_real_magic_headers() {
    let scenario = scenario_root().join("public-firmware-binwalk-magic");
    let pattern_file = scenario.join("patterns.pcre");
    let blobs_dir = scenario.join("blobs");

    let output = run_precursor(
        &[
            "-p",
            pattern_file.to_str().expect("pattern path utf8"),
            "-f",
            blobs_dir.to_str().expect("blobs path utf8"),
            "--input-mode",
            "binary",
            "-t",
            "-d",
            "--similarity-mode",
            "lzjd",
            "-P",
        ],
        "",
    );

    let reports = parse_ndjson(&output.stdout);
    assert_eq!(reports.len(), 4);
    let mut saw_gzip = false;
    let mut saw_romfs = false;
    let mut saw_squashfs = false;
    let mut saw_cramfs = false;
    for report in &reports {
        let Some(tags) = report.get("tags").and_then(Value::as_array) else {
            continue;
        };
        for tag in tags {
            match tag.as_str().unwrap_or_default() {
                "gzip_magic" => saw_gzip = true,
                "romfs_magic" => saw_romfs = true,
                "squashfs_magic" => saw_squashfs = true,
                "cramfs_magic" => saw_cramfs = true,
                _ => {}
            }
        }
    }
    assert!(saw_gzip, "expected gzip_magic tag");
    assert!(saw_romfs, "expected romfs_magic tag");
    assert!(saw_squashfs, "expected squashfs_magic tag");
    assert!(saw_cramfs, "expected cramfs_magic tag");
}

#[test]
fn foxit_pcap_extraction_script_matches_committed_payloads() {
    let tshark_available = Command::new("tshark")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !tshark_available {
        return;
    }

    let scenario = scenario_root().join("public-log4shell-foxit-pcap");
    let script = scenario.join("extract_payloads.sh");
    let pcap = scenario.join("ldap-uri-params-ev0.pcap");
    let expected =
        std::fs::read_to_string(scenario.join("payloads.string")).expect("read payloads");

    let output = Command::new("bash")
        .arg(script.to_str().expect("script path utf8"))
        .arg(pcap.to_str().expect("pcap path utf8"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run extraction script");

    assert!(
        output.status.success(),
        "extraction script failed with status {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let regenerated = String::from_utf8(output.stdout).expect("utf8 extraction output");
    assert_eq!(
        regenerated.trim_end(),
        expected.trim_end(),
        "regenerated payloads do not match committed payloads.string"
    );
}

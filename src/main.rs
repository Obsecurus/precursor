mod precursor;

use std::collections::HashSet;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

extern crate atomic_counter;
extern crate base64;
extern crate clap;
extern crate dashmap;
extern crate indicatif;
extern crate jaq_core;
extern crate pcre2;
extern crate rayon;
extern crate serde_json;
extern crate xxhash_rust;

use crate::precursor::inference::infer_protocol_candidates;
use crate::precursor::similarity::*;
use crate::precursor::util::*;

use atomic_counter::{AtomicCounter, ConsistentCounter};
use clap::{
    builder::PathBufValueParser, value_parser, Arg, ArgAction, ArgMatches, ColorChoice, Command,
};
use dashmap::DashMap;

use jaq_core::{parse, Ctx, Definitions, RcIter, Val};
use rayon::prelude::*;
use serde_json::{from_str, json, to_string, Map, Number, Value};

// Argument constants for CLI flags
const STATS: &str = "stats";
const TLSH: &str = "tlsh";
const TLSH_ALGORITHM: &str = "tlsh-algorithm";
const TLSH_DIFF: &str = "tlsh-diff";
const TLSH_LENGTH: &str = "tlsh-length";
const TLSH_DISTANCE: &str = "tlsh-distance";
const TLSH_SIM_ONLY: &str = "tlsh-sim-only";
const INPUT_FOLDER: &str = "input-folder";
const INPUT_MODE: &str = "input-mode";
const INPUT_BLOB: &str = "input-blob";
const INPUT_MODE_BASE64: &str = "base64";
const INPUT_MODE_STRING: &str = "string";
const INPUT_MODE_HEX: &str = "hex";
const INPUT_JSON_KEY: &str = "input-json-key";
const PATTERN_FILE: &str = "pattern-file";
const PATTERN: &str = "pattern";
const SIMILARITY_MODE: &str = "similarity-mode";
const SIMILARITY_MODE_TLSH: &str = "tlsh";
const SIMILARITY_MODE_LZJD: &str = "lzjd";
const SIMILARITY_MODE_MRSHV2: &str = "mrshv2";
const SIMILARITY_MODE_FBHASH: &str = "fbhash";
const PROTOCOL_HINTS: &str = "protocol-hints";
const PROTOCOL_HINTS_LIMIT: &str = "protocol-hints-limit";
const SINGLE_PACKET: &str = "single-packet";
const ABSTAIN_THRESHOLD: &str = "abstain-threshold";
const PROTOCOL_TOP_K: &str = "protocol-top-k";

fn main() {
    // Start execution timer
    let start = Instant::now();

    // Stats Variables
    let counter_inputs = Arc::new(ConsistentCounter::new(0));
    let counter_pcre_patterns = Arc::new(ConsistentCounter::new(0));
    let counter_tlsh_hashes = Arc::new(ConsistentCounter::new(0));
    let counter_tlsh_similarites = Arc::new(ConsistentCounter::new(0));
    let counter_pcre_matches = Arc::new(DashMap::new());
    let counter_pcre_matches_total = Arc::new(ConsistentCounter::new(0));
    let counter_unique_payloads = Arc::new(Mutex::new(HashSet::new()));
    let vec_payload_size_matched: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    let vec_payload_size: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    let vec_tlsh_disance: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));

    // Create a list to store tlsh::Tlsh objects
    let tlsh_list: Vec<SimilarityHash> = Vec::new();

    // Create map store payload reports by xxh3_64 hash
    let payload_reports = Map::new();

    // Create map store to store tlsh_reports by tlsh
    let tlsh_reports: DashMap<String, Value> = DashMap::new();
    let similarity_mode_help = if cfg!(feature = "similarity-mrshv2") {
        "Select the similarity backend. TLSH/LZJD/MRSHv2 are implemented; FBHash is scaffolded."
    } else {
        "Select the similarity backend. TLSH and LZJD are implemented; MRSHv2/FBHash are scaffolded."
    };

    // Create a clap::ArgMatches object to store the CLI arguments
    let cmd = Command::new("precursor")
    .about("Precursor is a PCRE2 payload tagging and similarity hashing CLI (TLSH/LZJD) for text, hex, or base64 input.")
    .color(ColorChoice::Auto)
    .long_about("Precursor currently supports the following TLSH algorithms:\n
                  1. Tlsh48_1\n
                  2. Tlsh128_1\n
                  3. Tlsh128_3\n
                  4. Tlsh256_1\n
                  5. Tlsh256_3\n
                  6. LZJD-style sketching (`--similarity-mode lzjd`)\n
                  \n
                  The -d flag performs pairwise distance calculations between every line of input provided. This is an expensive O(2^n) operation and can consume significant amounts of memory. You can optimize this by using appropriate PCRE2 pre-filters and choosing a smaller TLSH algorithm/sketch.")
    .arg(Arg::new(PATTERN)
        .help("Specify the PCRE2 pattern to be used, it must contain a single named capture group.")
        .required_unless_present(PATTERN_FILE)
        .index(1))
    .arg(Arg::new(INPUT_FOLDER)
        .short('f')
        .long(INPUT_FOLDER)
        .value_parser(PathBufValueParser::new())
        .help("Specify the path to the input folder.")
        .action(ArgAction::Set))
    .arg(Arg::new(INPUT_BLOB)
        .short('z')
        .long(INPUT_BLOB)
        .help("Process each input source as a single blob instead of splitting on newlines.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(PATTERN_FILE)
        .short('p')
        .long(PATTERN_FILE)
        .value_parser(PathBufValueParser::new())
        .help("Specify the path to the file containing PCRE2 patterns, one per line, each must contain a single named capture group.")
        .conflicts_with(PATTERN)
        .action(ArgAction::Set))
    .arg(Arg::new(TLSH)
        .short('t')
        .long(TLSH)
        .help("Calculate payload tlsh hash of the input payloads.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(TLSH_ALGORITHM)
        .short('a')
        .long(TLSH_ALGORITHM)
        .help("Specify the TLSH algorithm to use. The algorithms specify the bucket size in bytes and the checksum length in bits.")
        .value_parser(["128_1", "128_3", "256_1", "256_3", "48_1"])
        .action(ArgAction::Set)
        .default_value("48_1"))
    .arg(Arg::new(TLSH_DIFF)
        .short('d')
        .long(TLSH_DIFF)
        .help("Perform TLSH distance calculations between every line of input provided. This is an expensive O(2^n) operation and can consume significant amounts of memory. You can optimize this by using appropriate PCRE2 pre-filters and chosing a smaller TLSH algorithm.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(TLSH_SIM_ONLY)
        .short('y')
        .long(TLSH_SIM_ONLY)
        .help("Only output JSON for the payloads containing TLSH similarities.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(TLSH_DISTANCE)
        .short('x')
        .long(TLSH_DISTANCE)
        .value_parser(value_parser!(i32))
        .help("Specify the TLSH distance threshold for a match.")
        .action(ArgAction::Set)
        .default_value("100"))
    .arg(Arg::new(TLSH_LENGTH)
        .short('l')
        .long(TLSH_LENGTH)
        .help("This uses a TLSH algorithm that considered the payload length.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(SIMILARITY_MODE)
        .long(SIMILARITY_MODE)
        .help(similarity_mode_help)
        .value_parser([
            SIMILARITY_MODE_TLSH,
            SIMILARITY_MODE_LZJD,
            SIMILARITY_MODE_MRSHV2,
            SIMILARITY_MODE_FBHASH,
        ])
        .action(ArgAction::Set)
        .default_value(SIMILARITY_MODE_TLSH))
    .arg(Arg::new(PROTOCOL_HINTS)
        .long(PROTOCOL_HINTS)
        .help("Emit protocol-discovery hint JSON to STDERR for LLM-guided analysis loops.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(PROTOCOL_HINTS_LIMIT)
        .long(PROTOCOL_HINTS_LIMIT)
        .help("Limit the number of protocol hint candidates emitted.")
        .value_parser(value_parser!(usize))
        .default_value("25")
        .action(ArgAction::Set))
    .arg(Arg::new(SINGLE_PACKET)
        .short('P')
        .long(SINGLE_PACKET)
        .help("Enable single-packet protocol inference heuristics for matched payloads.")
        .action(ArgAction::SetTrue))
    .arg(Arg::new(ABSTAIN_THRESHOLD)
        .short('A')
        .long(ABSTAIN_THRESHOLD)
        .help("Confidence threshold below which protocol inference abstains as unknown.")
        .value_parser(value_parser!(f64))
        .default_value("0.65")
        .action(ArgAction::Set))
    .arg(Arg::new(PROTOCOL_TOP_K)
        .short('k')
        .long(PROTOCOL_TOP_K)
        .help("Maximum number of protocol candidates to include per report.")
        .value_parser(value_parser!(usize))
        .default_value("3")
        .action(ArgAction::Set))
    .arg(Arg::new(INPUT_MODE)
        .short('m')
        .long(INPUT_MODE)
        .help("Specify the payload mode as base64, string, or hex for stdin.")
        .value_parser([INPUT_MODE_BASE64, INPUT_MODE_STRING, INPUT_MODE_HEX])
        .action(ArgAction::Set)
        .default_value("base64"))
    .arg(Arg::new(INPUT_JSON_KEY)
        .short('j')
        .long(INPUT_JSON_KEY)
        .help("Specify the JQ-like pattern for parsing the input from the JSON input.")
        .action(ArgAction::Set))
    .arg(Arg::new(STATS)
        .short('s')
        .long(STATS)
        .help("Output statistics report.")
        .action(ArgAction::SetTrue));

    let args = cmd.get_matches();
    let similarity_mode_value = args
        .get_one::<String>(SIMILARITY_MODE)
        .map_or(SIMILARITY_MODE_TLSH, String::as_str);
    let similarity_mode = match SimilarityMode::from_str(similarity_mode_value) {
        Ok(mode) => mode,
        Err(err) => {
            eprintln!("Unable to parse similarity mode: {}", err);
            std::process::exit(2);
        }
    };

    let similarity_requested =
        args.get_flag(TLSH) || args.get_flag(TLSH_DIFF) || args.get_flag(TLSH_LENGTH);
    if similarity_requested {
        let mrshv2_enabled = cfg!(feature = "similarity-mrshv2");
        if similarity_mode == SimilarityMode::FbHash {
            eprintln!(
                "Similarity mode '{}' is scaffolded but not implemented yet. Use --{} {} or --{} {} for active hashing.",
                similarity_mode.as_str(),
                SIMILARITY_MODE,
                SIMILARITY_MODE_TLSH,
                SIMILARITY_MODE,
                SIMILARITY_MODE_LZJD
            );
            std::process::exit(2);
        }
        if similarity_mode == SimilarityMode::Mrshv2 && !mrshv2_enabled {
            eprintln!(
                "Similarity mode '{}' requires compiling with `--features similarity-mrshv2` and linking a native adapter. Use --{} {} or --{} {} for active hashing in this build.",
                similarity_mode.as_str(),
                SIMILARITY_MODE,
                SIMILARITY_MODE_TLSH,
                SIMILARITY_MODE,
                SIMILARITY_MODE_LZJD
            );
            std::process::exit(2);
        }
    }

    let tlsh_list = Mutex::new(tlsh_list);
    let payload_reports = Mutex::new(payload_reports);

    let patterns: Vec<String> =
        if let Some(pattern_file) = args.get_one::<std::path::PathBuf>(PATTERN_FILE) {
            match read_patterns(Some(pattern_file)) {
                Ok(patterns) => patterns,
                Err(err) => {
                    eprintln!(
                        "Unable to read pattern file {}: {}",
                        pattern_file.display(),
                        err
                    );
                    std::process::exit(2);
                }
            }
        } else if let Some(pattern) = args.get_one::<String>(PATTERN) {
            vec![pattern.to_string()]
        } else {
            eprintln!("Either a positional pattern or --pattern-file must be provided.");
            std::process::exit(2);
        };

    let mut compiled_patterns = Vec::with_capacity(patterns.len());
    for pattern in &patterns {
        match build_regex(pattern) {
            Ok(re) => compiled_patterns.push(re),
            Err(err) => {
                eprintln!("Invalid PCRE2 pattern '{}': {}", pattern, err);
                std::process::exit(2);
            }
        }
    }
    counter_pcre_patterns.add(compiled_patterns.len());

    if let Some(path) = args.get_one::<std::path::PathBuf>(INPUT_FOLDER) {
        if !path.is_dir() {
            eprintln!("-f path must be a folder: {}", path.display());
            return;
        }
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!("Unable to read directory {}: {}", path.display(), err);
                return;
            }
        };

        for entry_result in entries {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(err) => {
                    eprintln!("Unable to read directory entry: {}", err);
                    continue;
                }
            };
            let file_path: PathBuf = entry.path();
            if !file_path.is_file() {
                continue;
            }

            if args.get_flag(INPUT_BLOB) {
                let blob = match std::fs::read(&file_path) {
                    Ok(blob) => blob,
                    Err(err) => {
                        eprintln!("Unable to read blob file {}: {}", file_path.display(), err);
                        continue;
                    }
                };
                counter_inputs.inc();
                handle_blob(
                    blob.as_slice(),
                    &compiled_patterns,
                    &args,
                    &similarity_mode,
                    &tlsh_list,
                    &payload_reports,
                    &counter_pcre_matches,
                    &counter_tlsh_hashes,
                    &vec_payload_size,
                    &vec_payload_size_matched,
                    &counter_unique_payloads,
                    &counter_pcre_matches_total,
                );
                continue;
            }

            let file = match std::fs::File::open(&file_path) {
                Ok(file) => file,
                Err(err) => {
                    eprintln!("Unable to open file {}: {}", file_path.display(), err);
                    continue;
                }
            };
            let reader = std::io::BufReader::new(file);
            for line_result in reader.lines() {
                let line = match line_result {
                    Ok(line) => line,
                    Err(err) => {
                        eprintln!("Unable to read line from {}: {}", file_path.display(), err);
                        continue;
                    }
                };
                counter_inputs.inc();
                handle_line(
                    &line,
                    &compiled_patterns,
                    &args,
                    &similarity_mode,
                    &tlsh_list,
                    &payload_reports,
                    &counter_pcre_matches,
                    &counter_tlsh_hashes,
                    &vec_payload_size,
                    &vec_payload_size_matched,
                    &counter_unique_payloads,
                    &counter_pcre_matches_total,
                );
            }
        }
    } else {
        let stdin = io::stdin();
        if args.get_flag(INPUT_BLOB) {
            let mut blob = Vec::new();
            let mut lock = stdin.lock();
            if let Err(err) = lock.read_to_end(&mut blob) {
                eprintln!("Unable to read blob from STDIN: {}", err);
                return;
            }
            counter_inputs.inc();
            handle_blob(
                blob.as_slice(),
                &compiled_patterns,
                &args,
                &similarity_mode,
                &tlsh_list,
                &payload_reports,
                &counter_pcre_matches,
                &counter_tlsh_hashes,
                &vec_payload_size,
                &vec_payload_size_matched,
                &counter_unique_payloads,
                &counter_pcre_matches_total,
            );
        } else {
            stdin
                .lock()
                .lines()
                .filter_map(|line| match line {
                    Ok(value) => Some(value),
                    Err(err) => {
                        eprintln!("Unable to read line from STDIN: {}", err);
                        None
                    }
                })
                .collect::<Vec<String>>()
                .par_iter()
                .for_each(|line| {
                    counter_inputs.inc();
                    handle_line(
                        line,
                        &compiled_patterns,
                        &args,
                        &similarity_mode,
                        &tlsh_list,
                        &payload_reports,
                        &counter_pcre_matches,
                        &counter_tlsh_hashes,
                        &vec_payload_size,
                        &vec_payload_size_matched,
                        &counter_unique_payloads,
                        &counter_pcre_matches_total,
                    );
                });
        }
    }

    if args.get_flag(TLSH_DIFF) {
        run_hash_diffs(
            &tlsh_list,
            &args,
            &similarity_mode,
            &tlsh_reports,
            &counter_tlsh_similarites,
            &vec_tlsh_disance,
        );
    }

    generate_reports(&tlsh_reports, &payload_reports, &args);
    if args.get_flag(PROTOCOL_HINTS) {
        emit_protocol_hints(&payload_reports, &tlsh_reports, &args, &similarity_mode);
    }

    if args.get_flag(STATS) {
        // TODO: Potentially optimize so that we don't waist CPU on creation of stats (counter, incrementers, etc.) unless this flag is passed.
        let default_empty = 0;
        let end = Instant::now();
        let duration = end.duration_since(start);
        let duration_in_seconds = duration.as_secs_f32();
        let formated_duration: String = format!("{:.2}", duration_in_seconds);

        // Payloads Matched
        let (
            avg_payload_size_matched,
            min_payload_size_matched,
            max_payload_size_matched,
            p95_payload_size_matched,
            total_payload_size_matched,
        ) = match vec_payload_size_matched.lock() {
            Ok(payload_sizes_matched) => {
                let payload_sizes_matched_len = payload_sizes_matched.len();
                let avg_payload_size_matched = if payload_sizes_matched_len == 0 {
                    0.0
                } else {
                    payload_sizes_matched.iter().sum::<i64>() as f64
                        / payload_sizes_matched_len as f64
                };
                let min_payload_size_matched =
                    *payload_sizes_matched.iter().min().unwrap_or(&default_empty);
                let max_payload_size_matched =
                    *payload_sizes_matched.iter().max().unwrap_or(&default_empty);
                let mut sorted_payload_sizes_matched = payload_sizes_matched.clone();
                sorted_payload_sizes_matched.sort();
                let p95_payload_size_matched = if payload_sizes_matched_len > 1 {
                    sorted_payload_sizes_matched[(payload_sizes_matched_len * 95 / 100) - 1]
                } else if payload_sizes_matched_len == 1 {
                    sorted_payload_sizes_matched[0]
                } else {
                    default_empty
                };
                let total_payload_size_matched = payload_sizes_matched.iter().sum::<i64>();
                (
                    avg_payload_size_matched,
                    min_payload_size_matched,
                    max_payload_size_matched,
                    p95_payload_size_matched,
                    total_payload_size_matched,
                )
            }
            Err(err) => {
                eprintln!(
                    "Unable to read matched payload sizes due to poisoned lock: {}",
                    err
                );
                (0.0, default_empty, default_empty, default_empty, 0)
            }
        };

        // Raw Payloads
        let (
            avg_payload_size,
            min_payload_size,
            max_payload_size,
            p95_payload_size,
            total_payload_size,
        ) = match vec_payload_size.lock() {
            Ok(payload_sizes) => {
                let payload_sizes_len = payload_sizes.len();
                let avg_payload_size = if payload_sizes_len == 0 {
                    0.0
                } else {
                    payload_sizes.iter().sum::<i64>() as f64 / payload_sizes_len as f64
                };
                let min_payload_size = *payload_sizes.iter().min().unwrap_or(&default_empty);
                let max_payload_size = *payload_sizes.iter().max().unwrap_or(&default_empty);
                let mut sorted_payload_sizes = payload_sizes.clone();
                sorted_payload_sizes.sort();
                let p95_payload_size = if payload_sizes_len > 1 {
                    sorted_payload_sizes[(payload_sizes_len * 95 / 100) - 1]
                } else if payload_sizes_len == 1 {
                    sorted_payload_sizes[0]
                } else {
                    default_empty
                };
                let total_payload_size = payload_sizes.iter().sum::<i64>();
                (
                    avg_payload_size,
                    min_payload_size,
                    max_payload_size,
                    p95_payload_size,
                    total_payload_size,
                )
            }
            Err(err) => {
                eprintln!("Unable to read payload sizes due to poisoned lock: {}", err);
                (0.0, default_empty, default_empty, default_empty, 0)
            }
        };

        let processing_rate: String;
        if duration.as_secs() < 1 {
            let elapsed_millis = std::cmp::max(duration.as_millis() as i64, 1);
            processing_rate = format!("{}/ms", format_size(total_payload_size / elapsed_millis));
        } else {
            let elapsed_seconds = std::cmp::max(duration.as_secs() as i64, 1);
            processing_rate = format!("{}/s", format_size(total_payload_size / elapsed_seconds));
        }
        let default_empty_32 = 0_i32;
        // TLSH Hashes
        let mut compare_json: Value = Value::Null;
        let mut matches_json_array = Vec::new();
        for entry in counter_pcre_matches.iter() {
            let key = entry.key();
            let value = entry.value();
            let json_object: Value = json!({
                "Name": key,
                "Matches": *value
            });
            matches_json_array.push(json_object);
        }
        let matches_json = Value::Array(matches_json_array);
        if let Ok(tlsh_distances) = vec_tlsh_disance.lock() {
            if tlsh_distances.len() > 2 {
                let avg_tlsh_distance =
                    tlsh_distances.iter().sum::<i32>() as f32 / tlsh_distances.len() as f32;
                let min_tlsh_distance = tlsh_distances.iter().min().unwrap_or(&default_empty_32);
                let max_tlsh_distance = tlsh_distances.iter().max().unwrap_or(&default_empty_32);
                let mut sorted_tlsh_distances = tlsh_distances.clone();
                sorted_tlsh_distances.sort();
                let tlsh_distances_len = tlsh_distances.len();
                let p95_tlsh_distance = if tlsh_distances_len > 1 {
                    sorted_tlsh_distances[(tlsh_distances_len * 95 / 100) - 1]
                } else {
                    sorted_tlsh_distances[0]
                };
                compare_json = json!({
                    "Similarities": counter_tlsh_similarites.get(),
                    "AvgDistance": format!("{:.0}", avg_tlsh_distance),
                    "MinDistance": *min_tlsh_distance,
                    "MaxDistance": *max_tlsh_distance,
                    "P95Distance": p95_tlsh_distance,
                });
            }
        } else {
            eprintln!("Unable to read TLSH distances due to poisoned lock");
        }

        let unique_payload_count = match counter_unique_payloads.lock() {
            Ok(unique_payloads) => unique_payloads.len(),
            Err(err) => {
                eprintln!(
                    "Unable to read unique payload count due to poisoned lock: {}",
                    err
                );
                0
            }
        };
        let input_mode = args
            .get_one::<String>(INPUT_MODE)
            .map_or(INPUT_MODE_BASE64, String::as_str);
        let hash_function = args
            .get_one::<String>(TLSH_ALGORITHM)
            .map_or("48_1", String::as_str);
        let distance_threshold = args.get_one::<i32>(TLSH_DISTANCE).copied().unwrap_or(100);
        let input_json_key = args
            .get_one::<String>(INPUT_JSON_KEY)
            .map_or("", String::as_str);

        // Create a JSON object for the stats
        let stats = json!({
            "---PRECURSOR_STATISTICS---": "This JSON is output to STDERR so that you can parse stats seperate from the primary output.",
            "Input": {
                        "Count": counter_inputs.get(),
                        "Unique": unique_payload_count,
                        "AvgSize": format!("{:.0}", avg_payload_size),
                        "MinSize": min_payload_size,
                        "MaxSize": max_payload_size,
                        "P95Size": p95_payload_size,
                        "TotalSize": format_size(total_payload_size),},
            "Match": {
                        "Patterns": counter_pcre_patterns.get(),
                        "TotalMatches": counter_pcre_matches_total.get(),
                        "Matches": matches_json,
                        "HashesGenerated": counter_tlsh_hashes.get(),
                        "AvgSize": format!("{:.0}", avg_payload_size_matched),
                        "MinSize": min_payload_size_matched,
                        "MaxSize": max_payload_size_matched,
                        "P95Size": p95_payload_size_matched,
                        "TotalSize": format_size(total_payload_size_matched),},
            "Compare": compare_json,
            "Environment": {
                        "Version": env!("CARGO_PKG_VERSION"),
                        "DurationSeconds": formated_duration,
                        "ProcessingRate": processing_rate,
                        "SimilarityMode": similarity_mode.as_str(),
                        "InputMode": input_mode,
                        "HashFunction": hash_function,
                        "DistanceThreshold": distance_threshold,
                        "DiffEnabled": args.get_flag(TLSH_DIFF),
                        "OnlyOutputSimilar": args.get_flag(TLSH_SIM_ONLY),
                        "LengthEnabled": args.get_flag(TLSH_LENGTH),
                        "InputJSONKey": input_json_key,
                        "SinglePacketInference": args.get_flag(SINGLE_PACKET),
                        "AbstainThreshold": args.get_one::<f64>(ABSTAIN_THRESHOLD).copied().unwrap_or(0.65),
                        "ProtocolTopK": args.get_one::<usize>(PROTOCOL_TOP_K).copied().unwrap_or(3),
                        },
            }
        );

        // Serialize the JSON object as a pretty-printed String
        match serde_json::to_string_pretty(&stats) {
            Ok(pretty_json) => {
                let mut stderr = std::io::stderr();
                if let Err(err) = writeln!(&mut stderr, "{}", pretty_json) {
                    eprintln!("Error printing JSON to STDERR: {}", err);
                    return;
                }
                if let Err(err) = stderr.flush() {
                    eprintln!("Error flushing STDERR buffer: {}", err);
                }
            }
            Err(err) => {
                eprintln!(
                    "Error converting JSON object to pretty-printed String: {}",
                    err
                );
            }
        }
    }
}

// Unpacks the reports from the shared mutex
// and performs TLSH hash lookups for the matches from the tlsh in the payload report./
fn emit_report(report: &Value) {
    let report_json = match to_string(report) {
        Ok(serialized) => serialized,
        Err(err) => {
            eprintln!("Unable to serialize report to JSON: {}", err);
            return;
        }
    };
    let mut stdout = io::stdout();
    if let Err(err) = writeln!(&mut stdout, "{}", report_json) {
        eprintln!("Error writing report to STDOUT: {}", err);
        return;
    }
    if let Err(err) = stdout.flush() {
        eprintln!("Error flushing STDOUT buffer: {}", err);
    }
}

fn apply_similarity_neighbor_boost(
    report: &mut Value,
    neighbor_count: usize,
    abstain_threshold: f64,
) {
    if neighbor_count == 0 {
        return;
    }
    let boost = ((neighbor_count as f64).ln_1p() * 0.08).min(0.25);
    if boost <= 0.0 {
        return;
    }
    let Some(candidates) = report
        .get_mut("protocol_candidates")
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    for candidate in candidates.iter_mut() {
        let current = candidate
            .get("score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let boosted = (current + boost).clamp(0.0, 0.99);
        if let Some(score) = Number::from_f64(boosted) {
            candidate["score"] = Value::Number(score);
        }
        if let Some(evidence) = candidate.get_mut("evidence").and_then(Value::as_array_mut) {
            evidence.push(Value::String(format!(
                "similarity cluster boost from {} neighbors",
                neighbor_count
            )));
        }
    }

    candidates.sort_by(|left, right| {
        let left_score = left.get("score").and_then(Value::as_f64).unwrap_or(0.0);
        let right_score = right.get("score").and_then(Value::as_f64).unwrap_or(0.0);
        right_score
            .partial_cmp(&left_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let top_summary = candidates.first().map(|top| {
        let top_score = top.get("score").and_then(Value::as_f64).unwrap_or(0.0);
        let top_protocol = top
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        (top_score, top_protocol)
    });

    if let Some((top_score, top_protocol)) = top_summary {
        let abstained = top_score < abstain_threshold.clamp(0.0, 1.0);
        if let Some(score) = Number::from_f64(top_score) {
            report["protocol_confidence"] = Value::Number(score);
        }
        report["protocol_abstained"] = Value::Bool(abstained);
        if abstained {
            report["protocol_label"] = Value::String("unknown".to_string());
        } else {
            report["protocol_label"] = Value::String(top_protocol);
        }
    }
}

fn generate_reports(
    tlsh_reports: &DashMap<String, Value>,
    payload_reports: &Mutex<Map<String, Value>>,
    args: &ArgMatches,
) {
    let payload_reports_guard = match payload_reports.lock() {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("Unable to acquire payload report lock: {}", err);
            return;
        }
    };
    for (xxh3_64_sum, report) in payload_reports_guard.iter() {
        let similarity_hash = report["similarity_hash"]
            .as_str()
            .or_else(|| report["tlsh"].as_str())
            .unwrap_or("");
        if !similarity_hash.is_empty() && args.get_flag(TLSH_DIFF) {
            let mut report_clone = report.clone();
            report_clone["xxh3_64_sum"] = json!(xxh3_64_sum.as_str());
            if let Some(tlsh_similarities) = tlsh_reports.get(similarity_hash) {
                report_clone["tlsh_similarities"] = tlsh_similarities.value().clone();
                if args.get_flag(SINGLE_PACKET) {
                    let neighbor_count = tlsh_similarities
                        .value()
                        .as_object()
                        .map(|obj| obj.len())
                        .unwrap_or(0);
                    let abstain_threshold = args
                        .get_one::<f64>(ABSTAIN_THRESHOLD)
                        .copied()
                        .unwrap_or(0.65);
                    apply_similarity_neighbor_boost(
                        &mut report_clone,
                        neighbor_count,
                        abstain_threshold,
                    );
                }
                // Print reports with TLSH hash and TLSH similarities.
                emit_report(&report_clone);
            } else if !args.get_flag(TLSH_SIM_ONLY) {
                // Print reports with TLSH hash but no TLSH similarities.
                emit_report(&report_clone);
            }
        } else if !args.get_flag(TLSH_SIM_ONLY) {
            // Print reports empty TLSH hashes
            let mut report_clone = report.clone();
            report_clone["xxh3_64_sum"] = json!(xxh3_64_sum.as_str());
            emit_report(&report_clone);
        }
    }
}

fn emit_protocol_hints(
    payload_reports: &Mutex<Map<String, Value>>,
    tlsh_reports: &DashMap<String, Value>,
    args: &ArgMatches,
    similarity_mode: &SimilarityMode,
) {
    let limit = args
        .get_one::<usize>(PROTOCOL_HINTS_LIMIT)
        .copied()
        .unwrap_or(25);
    let mut candidates: Vec<(usize, Value)> = Vec::new();
    let payload_reports_guard = match payload_reports.lock() {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!(
                "Unable to acquire payload report lock for protocol hints: {}",
                err
            );
            return;
        }
    };

    for (xxh3_64_sum, report) in payload_reports_guard.iter() {
        let similarity_hash = report["similarity_hash"]
            .as_str()
            .or_else(|| report["tlsh"].as_str())
            .unwrap_or("");
        if similarity_hash.is_empty() {
            continue;
        }
        let neighbor_count = tlsh_reports
            .get(similarity_hash)
            .and_then(|map| map.value().as_object().map(|obj| obj.len()))
            .unwrap_or(0);
        let tags = report
            .get("tags")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let protocol_label = report.get("protocol_label").cloned().unwrap_or(Value::Null);
        let protocol_confidence = report
            .get("protocol_confidence")
            .cloned()
            .unwrap_or(Value::Null);
        let protocol_abstained = report
            .get("protocol_abstained")
            .cloned()
            .unwrap_or(Value::Null);
        candidates.push((
            neighbor_count,
            json!({
                "xxh3_64_sum": xxh3_64_sum.as_str(),
                "similarity_hash": similarity_hash,
                "neighbor_count": neighbor_count,
                "tags": tags,
                "protocol_label": protocol_label,
                "protocol_confidence": protocol_confidence,
                "protocol_abstained": protocol_abstained,
            }),
        ));
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0));
    let candidate_json: Vec<Value> = candidates
        .into_iter()
        .take(limit)
        .map(|(_, value)| value)
        .collect();
    let hints = json!({
        "---PRECURSOR_PROTOCOL_HINTS---": "Candidate payload clusters for LLM-guided protocol discovery.",
        "SimilarityMode": similarity_mode.as_str(),
        "DistanceThreshold": args.get_one::<i32>(TLSH_DISTANCE).copied().unwrap_or(100),
        "Candidates": candidate_json
    });

    match serde_json::to_string_pretty(&hints) {
        Ok(serialized) => {
            let mut stderr = io::stderr();
            if let Err(err) = writeln!(&mut stderr, "{}", serialized) {
                eprintln!("Unable to emit protocol hints to STDERR: {}", err);
            }
        }
        Err(err) => {
            eprintln!("Unable to serialize protocol hints: {}", err);
        }
    }
}

fn run_hash_diffs(
    tlsh_list: &Mutex<Vec<SimilarityHash>>,
    args: &ArgMatches,
    similarity_mode: &SimilarityMode,
    tlsh_reports: &DashMap<String, Value>,
    counter_tlsh_similarites: &Arc<ConsistentCounter>,
    vec_tlsh_disance: &std::sync::Mutex<Vec<i32>>,
) {
    let tlsh_list_guard = match tlsh_list.lock() {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("Unable to acquire TLSH list lock: {}", err);
            return;
        }
    };
    let distance_threshold = match args.get_one::<i32>(TLSH_DISTANCE) {
        Some(distance) => *distance,
        None => {
            eprintln!("Unable to read TLSH distance threshold argument");
            return;
        }
    };
    let include_file_length_in_calculation = args.get_flag(TLSH_LENGTH);
    let similarity_mode_name = similarity_mode.as_str();
    tlsh_list_guard
        .par_iter()
        .enumerate()
        .for_each(|(i, tlsh_i)| {
            let mut local_tlsh_map = Map::new();
            for tlsh_j in tlsh_list_guard.iter().skip(i + 1) {
                let diff = match diff_similarity_hash(
                    tlsh_i,
                    tlsh_j,
                    include_file_length_in_calculation,
                ) {
                    Ok(distance) => distance,
                    Err(err) => {
                        eprintln!("Skipping {} diff: {}", similarity_mode_name, err);
                        continue;
                    }
                };
                if let Ok(mut diff_vec) = vec_tlsh_disance.lock() {
                    diff_vec.push(diff);
                } else {
                    eprintln!("Unable to record TLSH distance due to poisoned lock");
                }
                if diff <= distance_threshold {
                    counter_tlsh_similarites.inc();
                    let tlsh_hash_string = match tlsh_j.as_string() {
                        Ok(hash_string) => hash_string,
                        Err(err) => {
                            eprintln!("Unable to convert similarity hash to string: {}", err);
                            continue;
                        }
                    };
                    let diff_number: Number = diff.into();

                    local_tlsh_map.insert(tlsh_hash_string, Value::Number(diff_number));
                }
            }
            let tlsh_hash_string = match tlsh_i.as_string() {
                Ok(hash_string) => hash_string,
                Err(err) => {
                    eprintln!("Unable to convert similarity hash to string: {}", err);
                    return;
                }
            };
            tlsh_reports.insert(tlsh_hash_string, Value::Object(local_tlsh_map));
        });
}

fn decode_payload_from_json_expression(
    raw_json: &str,
    payload_key: &str,
    input_mode: &str,
) -> Result<(Vec<u8>, Value), String> {
    let line_json: Value =
        from_str(raw_json).map_err(|err| format!("Unable to parse input as JSON: {}", err))?;

    let json_clone = if line_json.is_object() {
        line_json.clone()
    } else {
        let mut wrapped = Map::new();
        wrapped.insert("input".to_string(), line_json.clone());
        Value::Object(wrapped)
    };

    let defs = Definitions::core();
    let mut errs = Vec::new();
    let Some(parsed_filter) = parse::parse(payload_key, parse::main()).0 else {
        return Err(format!(
            "Unable to parse JSON key expression: {:?}",
            payload_key
        ));
    };
    let f = defs.finish(parsed_filter, Vec::new(), &mut errs);
    if !errs.is_empty() {
        return Err(format!(
            "Unable to compile JSON key expression {:?}: {:?}",
            payload_key, errs
        ));
    }

    let inputs = RcIter::new(core::iter::empty());
    let mut out = f.run(Ctx::new([], &inputs), Val::from(line_json));
    let payload = match out.next() {
        Some(Ok(v)) => {
            let v_str = v.to_string();
            get_payload(&v_str, input_mode).map_err(|err| {
                format!(
                    "Unable to decode payload from JSON key {:?}: {}",
                    payload_key, err
                )
            })?
        }
        Some(Err(e)) => {
            return Err(format!(
                "Unable to parse JSON pattern: {:?} with error: {:?}",
                payload_key, e
            ));
        }
        None => {
            return Err(format!(
                "No valid JSON was found for pattern: {:?}",
                payload_key
            ));
        }
    };

    Ok((payload, json_clone))
}

fn process_decoded_payload(
    payload: Vec<u8>,
    mut json_clone: Value,
    patterns: &[pcre2::bytes::Regex],
    args: &ArgMatches,
    similarity_mode: &SimilarityMode,
    tlsh_list: &Mutex<Vec<SimilarityHash>>,
    payload_reports: &Mutex<Map<String, Value>>,
    counter_pcre_matches: &Arc<DashMap<String, i64>>,
    counter_tlsh_hashes: &Arc<ConsistentCounter>,
    vec_payload_size: &std::sync::Mutex<Vec<i64>>,
    vec_payload_size_matched: &std::sync::Mutex<Vec<i64>>,
    counter_unique_payloads: &Arc<Mutex<HashSet<u64>>>,
    counter_pcre_matches_total: &Arc<ConsistentCounter>,
) {
    if let Ok(mut payload_sizes) = vec_payload_size.lock() {
        payload_sizes.push(payload.len() as i64);
    } else {
        eprintln!("Unable to record payload size due to poisoned lock");
        return;
    }

    let (xxh3_64_sum, xxh3_64_sum_string) = xxh3_64_hex(payload.clone());
    if let Ok(mut unique_payloads) = counter_unique_payloads.lock() {
        unique_payloads.insert(xxh3_64_sum);
    } else {
        eprintln!("Unable to record unique payload due to poisoned lock");
        return;
    }

    let mut matched_capture_groups: Vec<Value> = Vec::new();
    let mut matched_tag_names: Vec<String> = Vec::new();
    let mut match_exists = false;

    for re in patterns.iter() {
        let result = re
            .captures_iter(payload.as_slice())
            .filter_map(|res| res.ok())
            .any(|caps| {
                if let Ok(mut payload_sizes_matched) = vec_payload_size_matched.lock() {
                    payload_sizes_matched.push(payload.len() as i64);
                } else {
                    eprintln!("Unable to record matched payload size due to poisoned lock");
                }
                counter_pcre_matches_total.inc();
                let mut found_match = false;
                for name in re.capture_names() {
                    if let Some(name) = name {
                        if caps.name(name).is_some() {
                            // Here we increment a counter for each of the capture group names from the PCRE2 patterns.
                            let tag_name = name.to_string();
                            let mut count =
                                counter_pcre_matches.entry(tag_name.clone()).or_insert(0);
                            *count += 1;
                            matched_capture_groups.push(Value::String(tag_name.clone()));
                            matched_tag_names.push(tag_name);
                            found_match = true;
                        }
                    }
                }
                found_match
            });
        if result {
            match_exists = true;
        }
    }

    let mut json_tlsh_hash: Value = Value::String(String::new());
    let tlsh_algorithm = match args.get_one::<String>(TLSH_ALGORITHM) {
        Some(algorithm) => algorithm,
        None => {
            eprintln!("Unable to read TLSH algorithm argument");
            return;
        }
    };
    if match_exists {
        // We only calculate TLSH hashes and push to the global TLSH list
        // If the payload passes the pattern_match gate
        // This helps us acchieve a massive reduction in work for TLSH computation
        if args.get_flag(TLSH) || args.get_flag(TLSH_DIFF) || args.get_flag(TLSH_LENGTH) {
            match calculate_similarity_hash(payload.as_slice(), similarity_mode, tlsh_algorithm) {
                Ok(hash) => {
                    counter_tlsh_hashes.inc();
                    let hash_as_string = hash.as_string();
                    if let Ok(mut tlsh_hashes) = tlsh_list.lock() {
                        tlsh_hashes.push(hash);
                    } else {
                        eprintln!("Unable to record TLSH hash due to poisoned lock");
                        return;
                    }
                    if let Ok(tlsh_hash_string) = hash_as_string {
                        json_tlsh_hash = Value::String(tlsh_hash_string);
                    } else {
                        eprintln!("Unable to convert similarity hash to UTF-8 string");
                    }
                }
                Err(err) => {
                    eprintln!(
                        "Unable to calculate similarity hash using mode {}: {}",
                        similarity_mode.as_str(),
                        err
                    );
                }
            };
        }

        /*
        Create JSON output for payload only when match exists
        */
        let json_tlsh_hash_clone = json_tlsh_hash.clone();
        if json_tlsh_hash_clone.as_str().is_none() {
            json_clone["tlsh"] = Value::String(String::new());
            json_clone["similarity_hash"] = Value::String(String::new());
        } else {
            json_clone["tlsh"] = json_tlsh_hash.clone();
            json_clone["similarity_hash"] = json_tlsh_hash.clone();
        }
        json_clone["tags"] = Value::Array(matched_capture_groups);
        if args.get_flag(SINGLE_PACKET) {
            let abstain_threshold = args
                .get_one::<f64>(ABSTAIN_THRESHOLD)
                .copied()
                .unwrap_or(0.65);
            let protocol_top_k = args.get_one::<usize>(PROTOCOL_TOP_K).copied().unwrap_or(3);
            let inference = infer_protocol_candidates(
                payload.as_slice(),
                &matched_tag_names,
                0,
                protocol_top_k,
                abstain_threshold,
            );

            json_clone["protocol_label"] = Value::String(inference.label);
            json_clone["protocol_abstained"] = Value::Bool(inference.abstained);
            json_clone["protocol_confidence"] = Number::from_f64(inference.confidence)
                .map(Value::Number)
                .unwrap_or_else(|| Value::Number(Number::from(0)));
            let protocol_candidates = inference
                .candidates
                .into_iter()
                .map(|candidate| {
                    let score_value = Number::from_f64(candidate.score)
                        .map(Value::Number)
                        .unwrap_or_else(|| Value::Number(Number::from(0)));
                    json!({
                        "protocol": candidate.protocol,
                        "score": score_value,
                        "evidence": candidate.evidence
                    })
                })
                .collect::<Vec<Value>>();
            json_clone["protocol_candidates"] = Value::Array(protocol_candidates);
        }
        // This is where we insert the finished per-payload report
        if let Ok(mut reports) = payload_reports.lock() {
            reports.insert(xxh3_64_sum_string, json_clone);
        } else {
            eprintln!("Unable to record payload report due to poisoned lock");
        }
    }
}

fn handle_blob(
    blob: &[u8],
    patterns: &[pcre2::bytes::Regex],
    args: &ArgMatches,
    similarity_mode: &SimilarityMode,
    tlsh_list: &Mutex<Vec<SimilarityHash>>,
    payload_reports: &Mutex<Map<String, Value>>,
    counter_pcre_matches: &Arc<DashMap<String, i64>>,
    counter_tlsh_hashes: &Arc<ConsistentCounter>,
    vec_payload_size: &std::sync::Mutex<Vec<i64>>,
    vec_payload_size_matched: &std::sync::Mutex<Vec<i64>>,
    counter_unique_payloads: &Arc<Mutex<HashSet<u64>>>,
    counter_pcre_matches_total: &Arc<ConsistentCounter>,
) {
    let input_mode = args
        .get_one::<String>(INPUT_MODE)
        .map_or(INPUT_MODE_BASE64, String::as_str);

    let (payload, json_clone) = if let Some(payload_key) = args.get_one::<String>(INPUT_JSON_KEY) {
        let blob_as_utf8 = match std::str::from_utf8(blob) {
            Ok(text) => text,
            Err(err) => {
                eprintln!(
                    "Unable to decode input blob as UTF-8 for JSON extraction: {}",
                    err
                );
                return;
            }
        };
        match decode_payload_from_json_expression(blob_as_utf8, payload_key, input_mode) {
            Ok(decoded) => decoded,
            Err(err) => {
                eprintln!("{}", err);
                return;
            }
        }
    } else {
        let payload = match input_mode {
            INPUT_MODE_STRING => blob.to_vec(),
            INPUT_MODE_BASE64 | INPUT_MODE_HEX => {
                let blob_as_utf8 = match std::str::from_utf8(blob) {
                    Ok(text) => text,
                    Err(err) => {
                        eprintln!(
                            "Unable to decode blob using input mode {}: {}",
                            input_mode, err
                        );
                        return;
                    }
                };
                let normalized: String = blob_as_utf8
                    .chars()
                    .filter(|ch| !ch.is_whitespace())
                    .collect();
                match get_payload(&normalized, input_mode) {
                    Ok(decoded) => decoded,
                    Err(err) => {
                        eprintln!(
                            "Unable to decode blob using input mode {}: {}",
                            input_mode, err
                        );
                        return;
                    }
                }
            }
            _ => {
                eprintln!("{} not a supported input mode.", input_mode);
                return;
            }
        };
        (payload, Value::Object(Map::new()))
    };

    process_decoded_payload(
        payload,
        json_clone,
        patterns,
        args,
        similarity_mode,
        tlsh_list,
        payload_reports,
        counter_pcre_matches,
        counter_tlsh_hashes,
        vec_payload_size,
        vec_payload_size_matched,
        counter_unique_payloads,
        counter_pcre_matches_total,
    );
}

fn handle_line(
    line: &str,
    patterns: &[pcre2::bytes::Regex],
    args: &ArgMatches,
    similarity_mode: &SimilarityMode,
    tlsh_list: &Mutex<Vec<SimilarityHash>>,
    payload_reports: &Mutex<Map<String, Value>>,
    counter_pcre_matches: &Arc<DashMap<String, i64>>,
    counter_tlsh_hashes: &Arc<ConsistentCounter>,
    vec_payload_size: &std::sync::Mutex<Vec<i64>>,
    vec_payload_size_matched: &std::sync::Mutex<Vec<i64>>,
    counter_unique_payloads: &Arc<Mutex<HashSet<u64>>>,
    counter_pcre_matches_total: &Arc<ConsistentCounter>,
) {
    let input_mode = args
        .get_one::<String>(INPUT_MODE)
        .map_or(INPUT_MODE_BASE64, String::as_str);
    let (payload, json_clone) = if let Some(payload_key) = args.get_one::<String>(INPUT_JSON_KEY) {
        match decode_payload_from_json_expression(line, payload_key, input_mode) {
            Ok(decoded) => decoded,
            Err(err) => {
                eprintln!("{}", err);
                return;
            }
        }
    } else {
        let payload = match get_payload(line, input_mode) {
            Ok(payload) => payload,
            Err(err) => {
                eprintln!(
                    "Unable to decode payload using input mode {}: {}",
                    input_mode, err
                );
                return;
            }
        };
        (payload, Value::Object(Map::new()))
    };

    process_decoded_payload(
        payload,
        json_clone,
        patterns,
        args,
        similarity_mode,
        tlsh_list,
        payload_reports,
        counter_pcre_matches,
        counter_tlsh_hashes,
        vec_payload_size,
        vec_payload_size_matched,
        counter_unique_payloads,
        counter_pcre_matches_total,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_similarity_neighbor_boost_updates_top_candidate() {
        let mut report = json!({
            "protocol_label": "unknown",
            "protocol_confidence": 0.50,
            "protocol_abstained": true,
            "protocol_candidates": [
                { "protocol": "http", "score": 0.50, "evidence": [] },
                { "protocol": "tls", "score": 0.40, "evidence": [] }
            ]
        });

        apply_similarity_neighbor_boost(&mut report, 10, 0.60);

        assert_eq!(report["protocol_label"], json!("http"));
        assert_eq!(report["protocol_abstained"], json!(false));
        let confidence = report["protocol_confidence"].as_f64().unwrap_or(0.0);
        assert!(confidence > 0.60);
        let evidence_len = report["protocol_candidates"][0]["evidence"]
            .as_array()
            .map_or(0, |e| e.len());
        assert!(evidence_len > 0);
    }

    #[test]
    fn test_apply_similarity_neighbor_boost_is_noop_for_empty_neighbors() {
        let mut report = json!({
            "protocol_label": "http",
            "protocol_confidence": 0.80,
            "protocol_abstained": false,
            "protocol_candidates": [
                { "protocol": "http", "score": 0.80, "evidence": [] }
            ]
        });

        apply_similarity_neighbor_boost(&mut report, 0, 0.60);

        assert_eq!(report["protocol_label"], json!("http"));
        assert_eq!(report["protocol_abstained"], json!(false));
        let confidence = report["protocol_confidence"].as_f64().unwrap_or(0.0);
        assert!((confidence - 0.80).abs() < f64::EPSILON);
    }
}

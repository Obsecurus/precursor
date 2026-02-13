fn main() {
    set_git_revision_hash();
    set_windows_exe_options();
    set_mrshv2_linking();
}

/// Embed a Windows manifest and set some linker options.
///
/// The main reason for this is to enable long path support on Windows. This
/// still, I believe, requires enabling long path support in the registry. But
/// if that's enabled, then this will let precursor use C:\... style paths that
/// are longer than 260 characters.
fn set_windows_exe_options() {
    static MANIFEST: &str = "pkg/windows/Manifest.xml";

    let Ok(target_os) = std::env::var("CARGO_CFG_TARGET_OS") else {
        return;
    };
    let Ok(target_env) = std::env::var("CARGO_CFG_TARGET_ENV") else {
        return;
    };
    if !(target_os == "windows" && target_env == "msvc") {
        return;
    }

    let Ok(mut manifest) = std::env::current_dir() else {
        return;
    };
    manifest.push(MANIFEST);
    let Some(manifest) = manifest.to_str() else {
        return;
    };

    println!("cargo:rerun-if-changed={}", MANIFEST);
    // Embed the Windows application manifest file.
    println!("cargo:rustc-link-arg-bin=precursor=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bin=precursor=/MANIFESTINPUT:{manifest}");
    // Turn linker warnings into errors. Helps debugging, otherwise the
    // warnings get squashed (I believe).
    println!("cargo:rustc-link-arg-bin=precursor=/WX");
}

/// Make the current git hash available to the build as the environment
/// variable `PRECURSOR_BUILD_GIT_HASH`.
fn set_git_revision_hash() {
    use std::process::Command;

    let args = &["rev-parse", "--short=10", "HEAD"];
    let Ok(output) = Command::new("git").args(args).output() else {
        return;
    };
    let rev = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if rev.is_empty() {
        return;
    }
    println!("cargo:rustc-env=PRECURSOR_BUILD_GIT_HASH={}", rev);
}

/// Configure optional MRSHv2 adapter linking when the feature is enabled.
///
/// The Rust MRSHv2 backend links against a tiny adapter ABI:
/// `precursor_mrshv2_hash`, `precursor_mrshv2_diff`, `precursor_mrshv2_free`,
/// and `precursor_mrshv2_last_error`.
///
/// The library name defaults to `precursor_mrshv2` and can be overridden with
/// `PRECURSOR_MRSHV2_LIB_NAME`. An extra search directory can be provided via
/// `PRECURSOR_MRSHV2_LIB_DIR`.
fn set_mrshv2_linking() {
    if std::env::var_os("CARGO_FEATURE_SIMILARITY_MRSHV2").is_none() {
        return;
    }
    println!("cargo:rerun-if-env-changed=PRECURSOR_MRSHV2_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PRECURSOR_MRSHV2_LIB_NAME");

    if let Ok(lib_dir) = std::env::var("PRECURSOR_MRSHV2_LIB_DIR") {
        if !lib_dir.is_empty() {
            println!("cargo:rustc-link-search=native={}", lib_dir);
        }
    }

    let lib_name = std::env::var("PRECURSOR_MRSHV2_LIB_NAME")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "precursor_mrshv2".to_string());
    println!("cargo:rustc-link-lib=dylib={}", lib_name);
}

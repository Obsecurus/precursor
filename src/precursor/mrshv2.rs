#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mrshv2Hash {
    digest: String,
    payload_len: usize,
}

impl Mrshv2Hash {
    pub fn as_string(&self) -> &str {
        self.digest.as_str()
    }

    #[cfg(feature = "similarity-mrshv2")]
    pub fn payload_len(&self) -> usize {
        self.payload_len
    }
}

#[cfg(feature = "similarity-mrshv2")]
mod native {
    use super::Mrshv2Hash;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_uchar};
    use std::sync::{Mutex, OnceLock};

    extern "C" {
        fn precursor_mrshv2_hash(
            payload: *const c_uchar,
            payload_len: usize,
            out_digest: *mut *mut c_char,
        ) -> c_int;
        fn precursor_mrshv2_diff(
            left_digest: *const c_char,
            right_digest: *const c_char,
            out_distance: *mut c_int,
        ) -> c_int;
        fn precursor_mrshv2_free(value: *mut c_char);
        fn precursor_mrshv2_last_error() -> *const c_char;
    }

    fn ffi_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn last_error_message(default_message: &str) -> String {
        unsafe {
            let ptr = precursor_mrshv2_last_error();
            if ptr.is_null() {
                return default_message.to_string();
            }
            let message = CStr::from_ptr(ptr).to_string_lossy().trim().to_string();
            if message.is_empty() {
                default_message.to_string()
            } else {
                message
            }
        }
    }

    pub fn calculate_mrshv2_hash(payload: &[u8]) -> Result<Mrshv2Hash, String> {
        if payload.is_empty() {
            return Err("MRSHv2 hash requires a non-empty payload".to_string());
        }

        let _guard = ffi_lock()
            .lock()
            .map_err(|_| "MRSHv2 adapter lock is poisoned".to_string())?;

        let mut out_digest: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            precursor_mrshv2_hash(
                payload.as_ptr() as *const c_uchar,
                payload.len(),
                &mut out_digest as *mut *mut c_char,
            )
        };
        if rc != 0 {
            if !out_digest.is_null() {
                unsafe {
                    precursor_mrshv2_free(out_digest);
                }
            }
            return Err(last_error_message(
                "MRSHv2 adapter failed to compute hash; check linked native adapter",
            ));
        }
        if out_digest.is_null() {
            return Err("MRSHv2 adapter returned an empty digest pointer".to_string());
        }

        let digest_result = unsafe { CStr::from_ptr(out_digest) }
            .to_str()
            .map(|value| value.to_string())
            .map_err(|err| format!("MRSHv2 adapter returned non UTF-8 digest: {}", err));

        unsafe {
            precursor_mrshv2_free(out_digest);
        }
        let digest = digest_result?;

        Ok(Mrshv2Hash {
            digest,
            payload_len: payload.len(),
        })
    }

    pub fn diff_mrshv2_hash(
        left: &Mrshv2Hash,
        right: &Mrshv2Hash,
        include_file_length: bool,
    ) -> Result<i32, String> {
        let _guard = ffi_lock()
            .lock()
            .map_err(|_| "MRSHv2 adapter lock is poisoned".to_string())?;

        let left_digest = CString::new(left.digest.as_str())
            .map_err(|err| format!("MRSHv2 left digest contains embedded NUL: {}", err))?;
        let right_digest = CString::new(right.digest.as_str())
            .map_err(|err| format!("MRSHv2 right digest contains embedded NUL: {}", err))?;

        let mut distance: c_int = 0;
        let rc = unsafe {
            precursor_mrshv2_diff(
                left_digest.as_ptr(),
                right_digest.as_ptr(),
                &mut distance as *mut c_int,
            )
        };
        if rc != 0 {
            return Err(last_error_message(
                "MRSHv2 adapter failed to diff digests; check linked native adapter",
            ));
        }

        let mut normalized = (distance as i32).clamp(0, 100);
        if include_file_length {
            let max_len = left.payload_len().max(right.payload_len()) as f64;
            if max_len > 0.0 {
                let len_delta = left.payload_len().abs_diff(right.payload_len()) as f64;
                let len_penalty = ((len_delta / max_len) * 10.0).round() as i32;
                normalized = (normalized + len_penalty).clamp(0, 100);
            }
        }

        Ok(normalized)
    }
}

#[cfg(not(feature = "similarity-mrshv2"))]
mod native {
    use super::Mrshv2Hash;

    pub fn calculate_mrshv2_hash(_payload: &[u8]) -> Result<Mrshv2Hash, String> {
        Err(
            "MRSHv2 support is disabled in this build. Recompile with `--features similarity-mrshv2` and provide a native adapter library."
                .to_string(),
        )
    }

    pub fn diff_mrshv2_hash(
        _left: &Mrshv2Hash,
        _right: &Mrshv2Hash,
        _include_file_length: bool,
    ) -> Result<i32, String> {
        Err(
            "MRSHv2 support is disabled in this build. Recompile with `--features similarity-mrshv2` and provide a native adapter library."
                .to_string(),
        )
    }
}

pub use native::{calculate_mrshv2_hash, diff_mrshv2_hash};

#[cfg(all(test, feature = "similarity-mrshv2"))]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_mrshv2_hash_prefix() {
        let hash = calculate_mrshv2_hash(b"GET / HTTP/1.1\r\nHost: example.org\r\n")
            .expect("expected mrshv2 hash");
        assert!(hash.as_string().starts_with("mrshv2:"));
    }

    #[test]
    fn test_diff_mrshv2_hash_identical_is_zero() {
        let left = calculate_mrshv2_hash(b"AAAAABBBBB").expect("expected left hash");
        let right = calculate_mrshv2_hash(b"AAAAABBBBB").expect("expected right hash");
        let distance = diff_mrshv2_hash(&left, &right, false).expect("expected distance");
        assert_eq!(distance, 0);
    }
}

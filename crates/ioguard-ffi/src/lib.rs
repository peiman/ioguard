//! C-ABI foreign function interface for ioguard.
//!
//! Exposes two functions:
//! - [`ioguard_scan`]: scan text, return heap-allocated Contract-A JSON
//! - [`ioguard_free`]: free a string returned by [`ioguard_scan`]

use std::ffi::{c_char, CStr, CString};

use ioguard_core::{Category, Direction, ScanOptions};

// ---------------------------------------------------------------------------
// FFI-facing options struct (deserializable from caller-supplied JSON)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct FfiScanOptions {
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    enabled_categories: Option<Vec<String>>,
    #[serde(default)]
    locale: Option<String>,
}

impl FfiScanOptions {
    fn into_scan_options(self) -> ScanOptions {
        let direction = match self.direction.as_deref() {
            Some("input") => Direction::Input,
            Some("output") => Direction::Output,
            _ => Direction::Both,
        };

        let enabled_categories = match self.enabled_categories {
            Some(cats) if !cats.is_empty() => cats
                .iter()
                .filter_map(|s| match s.as_str() {
                    "secret" => Some(Category::Secret),
                    "unicode_tags" => Some(Category::UnicodeTags),
                    "zero_width" => Some(Category::ZeroWidth),
                    "bidi" => Some(Category::Bidi),
                    "homoglyph" => Some(Category::Homoglyph),
                    "special_token" => Some(Category::SpecialToken),
                    _ => None,
                })
                .collect(),
            _ => ScanOptions::default().enabled_categories,
        };

        ScanOptions {
            direction,
            enabled_categories,
            locale: self.locale,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a Rust `&str` to a heap-allocated C string.
/// Returns null on interior NUL (should never happen with JSON).
fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Parse `opts_json` into `ScanOptions`. NULL, empty, or invalid JSON → defaults.
///
/// # Safety
/// `opts_json` must be either null or a valid pointer to a NUL-terminated C string.
unsafe fn parse_opts(opts_json: *const c_char) -> ScanOptions {
    if opts_json.is_null() {
        return ScanOptions::default();
    }
    let c_str = unsafe { CStr::from_ptr(opts_json) };
    let bytes = c_str.to_bytes();
    if bytes.is_empty() {
        return ScanOptions::default();
    }
    match serde_json::from_slice::<FfiScanOptions>(bytes) {
        Ok(ffi_opts) => ffi_opts.into_scan_options(),
        Err(_) => ScanOptions::default(),
    }
}

// ---------------------------------------------------------------------------
// Public C-ABI
// ---------------------------------------------------------------------------

/// Scan text for prompt-injection and secret-leak indicators.
///
/// # Arguments
/// - `text`: pointer to UTF-8 bytes (not necessarily NUL-terminated).
/// - `len`: number of bytes to read from `text`.
/// - `opts_json`: NUL-terminated JSON string for scan options, or NULL for defaults.
///
/// # Returns
/// A heap-allocated NUL-terminated JSON string (Contract-A schema). Ownership
/// transfers to the caller, who **MUST** free it via [`ioguard_free`].
///
/// Error conventions:
/// - NULL `text` → returns `{"error":"null input pointer"}` (caller must free)
/// - Invalid UTF-8 → returns `{"error":"invalid utf-8 input"}` (caller must free)
/// - Caught panic → returns NULL (nothing to free)
/// - Serialization failure → returns `{"error":"serialization failed"}` (caller must free)
///
/// # Safety
/// - `text` must be NULL or point to at least `len` readable bytes.
/// - `opts_json` must be NULL or a valid pointer to a NUL-terminated C string.
/// - The returned pointer must be freed exactly once via [`ioguard_free`].
#[no_mangle]
pub unsafe extern "C" fn ioguard_scan(
    text: *const u8,
    len: usize,
    opts_json: *const c_char,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        // Panic backdoor for FFI boundary testing.
        // When opts_json == "__test_panic" (a magic test sentinel), panic deliberately
        // so that `catch_unwind` can be verified. No real caller passes this string.
        if !opts_json.is_null() {
            let cs = unsafe { CStr::from_ptr(opts_json) };
            if cs.to_bytes() == b"__test_panic" {
                panic!("deliberate test panic for FFI boundary verification");
            }
        }

        // NULL text → error JSON (still heap-allocated; caller must free)
        if text.is_null() {
            return to_c_string(r#"{"error":"null input pointer"}"#);
        }

        // Build `&[u8]` from the raw pointer + length.
        let slice = unsafe { std::slice::from_raw_parts(text, len) };

        // Validate UTF-8.
        let text_str = match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return to_c_string(r#"{"error":"invalid utf-8 input"}"#),
        };

        // Parse caller-supplied options (NULL / empty / invalid → defaults).
        let opts = unsafe { parse_opts(opts_json) };

        // Run the detection pipeline.
        let scan_result = ioguard_core::scan(text_str, &opts);

        // Serialize to Contract-A JSON and hand ownership to the caller.
        match serde_json::to_string(&scan_result) {
            Ok(json) => to_c_string(&json),
            Err(_) => to_c_string(r#"{"error":"serialization failed"}"#),
        }
    });

    match result {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(), // panic caught → NULL
    }
}

/// Free a JSON string previously returned by [`ioguard_scan`].
///
/// # Safety
/// - `json` must be NULL or a pointer previously returned by [`ioguard_scan`].
/// - Each non-NULL pointer must be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn ioguard_free(json: *mut c_char) {
    if !json.is_null() {
        drop(unsafe { CString::from_raw(json) });
    }
}

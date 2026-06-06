//! Integration tests for logging::init().
//!
//! Each test runs in a separate process (cargo test runs each test file
//! as a separate binary), so we can call init() once per file without
//! conflicting with other tests that set the global subscriber.
//!
//! This file tests the file-logging path — the code at 59% coverage.

use ckeletin::logging::{init, LogConfig};
use std::fs;

#[test]
fn init_with_file_logging_creates_log_file_and_returns_guard() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("test.log");

    let config = LogConfig {
        console_level: "off".to_string(), // suppress stderr in test
        file_enabled: true,
        file_path: log_path.to_str().unwrap().to_string(),
        file_level: "debug".to_string(),
    };

    let guard = init(&config);
    assert!(guard.is_ok(), "init() should succeed with valid file path");

    // Emit a tracing event — it should land in the file
    tracing::info!(test = "logging_init", "test event");

    // Drop the guard to flush the non-blocking writer
    drop(guard);

    // The log directory should exist (created by init)
    assert!(dir.path().exists());

    // Check that SOME log file was created in the directory
    // (tracing-appender adds date suffixes, so the exact name varies)
    let entries: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .contains("test.log")
        })
        .collect();
    assert!(
        !entries.is_empty(),
        "Should have created at least one log file"
    );
}

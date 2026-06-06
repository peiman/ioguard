//! External process execution utilities.
//!
//! Provides simple wrappers around `std::process::Command` for running external
//! commands. These are infrastructure-level tools — they return raw strings, not
//! domain types. The CLI layer is responsible for parsing output into domain types.

use std::io;
use std::process::Command;

/// Runs a command and captures its stdout as a trimmed string.
///
/// Stderr is suppressed (piped to null). Returns an `io::Error` if the command
/// cannot be found or fails to execute. A non-zero exit code is reported as an
/// `io::Error` with `ErrorKind::Other`.
pub fn run_capture(cmd: &str, args: &[&str]) -> Result<String, io::Error> {
    let output = Command::new(cmd)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{} exited with status {}",
            cmd,
            output.status.code().unwrap_or(-1)
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(stdout)
}

/// Runs a command and returns `true` if it exits with code 0.
///
/// Stderr is suppressed. Returns `false` for non-zero exit codes **and** for
/// missing commands (i.e., this never panics).
pub fn run_success(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_capture_echo() {
        let result = run_capture("echo", &["hello"]).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn run_capture_trims_whitespace() {
        let result = run_capture("echo", &["  padded  "]).unwrap();
        assert_eq!(result, "padded");
    }

    #[test]
    fn run_capture_nonexistent_command() {
        let result = run_capture("this-command-does-not-exist-xyz", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn run_capture_failing_command() {
        let result = run_capture("false", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn run_success_true() {
        assert!(run_success("true", &[]));
    }

    #[test]
    fn run_success_false() {
        assert!(!run_success("false", &[]));
    }

    #[test]
    fn run_success_nonexistent_command() {
        assert!(!run_success("this-command-does-not-exist-xyz", &[]));
    }
}

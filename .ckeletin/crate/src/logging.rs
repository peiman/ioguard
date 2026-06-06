use std::path::{Path, PathBuf};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, registry, util::SubscriberInitExt, EnvFilter, Layer,
};

/// Guard that must be held for the lifetime of the application.
/// Dropping it flushes the non-blocking log file writer.
pub struct LogGuard {
    _guard: Option<WorkerGuard>,
}

/// Logging configuration.
pub struct LogConfig {
    /// Console (stderr) log level filter string. "off" to suppress.
    pub console_level: String,
    /// Enable file logging (audit stream).
    pub file_enabled: bool,
    /// Path to the log file.
    pub file_path: String,
    /// File log level filter string (typically "debug" or "trace").
    pub file_level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            console_level: "info".to_string(),
            file_enabled: false,
            file_path: "logs/app.log".to_string(),
            file_level: "debug".to_string(),
        }
    }
}

/// Build an EnvFilter from a level string, falling back to the provided default.
fn build_filter(level: &str, fallback: &str) -> EnvFilter {
    EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new(fallback))
}

/// Read an environment variable as an absolute path, if set and absolute.
fn env_abs(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os(name)?);
    p.is_absolute().then_some(p)
}

/// The user's home directory: `$HOME` (Unix) or `%USERPROFILE%` (Windows).
fn home() -> Option<PathBuf> {
    env_abs("HOME").or_else(|| env_abs("USERPROFILE"))
}

/// Pure config-home resolution given the candidate env values — unit-testable
/// without touching process-global env (which races under parallel tests).
fn config_home_from(xdg: Option<PathBuf>, home: Option<PathBuf>) -> PathBuf {
    xdg.or_else(|| home.map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"))
}

/// The user's config-home directory, XDG-style and uniform across platforms:
/// `$XDG_CONFIG_HOME` if set (and absolute), else `~/.config`. This is
/// `~/.config` even on macOS (we intentionally do not use `~/Library/Application
/// Support` here — that is the opt-in "platform" location). Falls back to a
/// relative `.config` only if the home directory cannot be determined.
fn config_home() -> PathBuf {
    config_home_from(env_abs("XDG_CONFIG_HOME"), home())
}

/// The OS-native application-data directory (no app segment yet):
/// `~/Library/Application Support` (macOS), `$XDG_DATA_HOME` or `~/.local/share`
/// (Linux/other Unix), `%APPDATA%` (Windows).
fn platform_data_home() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        home().map(|h| h.join("Library").join("Application Support"))
    }
    #[cfg(target_os = "windows")]
    {
        env_abs("APPDATA")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        env_abs("XDG_DATA_HOME").or_else(|| home().map(|h| h.join(".local").join("share")))
    }
}

/// Compute the per-app base directory the audit log is anchored under. Pure —
/// the base directories are injected — so it is unit-testable without touching
/// the environment.
fn audit_base_in(
    location: &str,
    app: &str,
    config_home: PathBuf,
    data_home: Option<PathBuf>,
) -> PathBuf {
    match location {
        // OS-native application-data dir: ~/Library/Application Support/<app>
        // (macOS), ~/.local/share/<app> (Linux), %APPDATA%\<app> (Windows).
        "platform" | "native" | "os" => data_home.unwrap_or(config_home).join(app),
        // Default: XDG config home, uniform across platforms — ~/.config/<app>.
        _ => config_home.join(app),
    }
}

/// Resolve where the audit log should live (CKSPEC-OUT-004).
///
/// An absolute `configured` path is honored verbatim. A relative one (the
/// default `logs/app.log`) is anchored under the per-app base directory chosen
/// by `location`: `"config"` → `~/.config/<app>` (default), `"platform"` → the
/// OS-native application-data directory. This keeps the audit log in a stable
/// per-user place instead of wherever the binary happens to be invoked.
pub fn resolve_audit_path(configured: &str, location: &str, app: &str) -> PathBuf {
    let p = Path::new(configured);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    audit_base_in(location, app, config_home(), platform_data_home()).join(p)
}

/// Prepare the log file directory and appender.
/// Returns (non_blocking_writer, guard) or an error if the directory can't be created.
fn prepare_file_appender(
    file_path: &str,
) -> Result<(tracing_appender::non_blocking::NonBlocking, WorkerGuard), std::io::Error> {
    let log_path = std::path::Path::new(file_path);
    let log_dir = log_path.parent().unwrap_or(std::path::Path::new("."));
    let log_name = log_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    std::fs::create_dir_all(log_dir)?;

    let file_appender = tracing_appender::rolling::daily(log_dir, log_name);
    Ok(tracing_appender::non_blocking(file_appender))
}

/// Initialize tracing with stderr (status stream) and optional file (audit stream).
///
/// CKSPEC-OUT-001: stderr for status, file for audit.
/// CKSPEC-OUT-004: shadow logging — output.rs emits tracing events that land here.
///
/// Returns a guard that must be held until shutdown (flushes file writer).
pub fn init(config: &LogConfig) -> Result<LogGuard, Box<dyn std::error::Error>> {
    let stderr_filter = build_filter(&config.console_level, "info");

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(true)
        .with_filter(stderr_filter);

    if config.file_enabled {
        let (non_blocking, guard) = prepare_file_appender(&config.file_path)?;

        let file_filter = build_filter(&config.file_level, "debug");

        let file_layer = fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_filter(file_filter);

        registry().with(stderr_layer).with(file_layer).init();

        Ok(LogGuard {
            _guard: Some(guard),
        })
    } else {
        registry().with(stderr_layer).init();

        Ok(LogGuard { _guard: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── LogConfig tests ─────────────────────────────────────────

    #[test]
    fn default_config_has_sane_values() {
        let config = LogConfig::default();
        assert_eq!(config.console_level, "info");
        assert!(!config.file_enabled);
        assert_eq!(config.file_path, "logs/app.log");
        assert_eq!(config.file_level, "debug");
    }

    #[test]
    fn config_allows_custom_values() {
        let config = LogConfig {
            console_level: "debug".to_string(),
            file_enabled: true,
            file_path: "/tmp/test.log".to_string(),
            file_level: "trace".to_string(),
        };
        assert_eq!(config.console_level, "debug");
        assert!(config.file_enabled);
        assert_eq!(config.file_level, "trace");
    }

    // ── build_filter tests ──────────────────────────────────────

    #[test]
    fn build_filter_accepts_valid_level() {
        let filter = build_filter("debug", "info");
        // Filter should accept debug-level events
        assert_eq!(format!("{filter}"), "debug");
    }

    #[test]
    fn build_filter_handles_all_standard_levels() {
        for level in &["trace", "debug", "info", "warn", "error", "off"] {
            let filter = build_filter(level, "info");
            assert_eq!(
                format!("{filter}"),
                *level,
                "Filter should match level {level}"
            );
        }
    }

    #[test]
    fn build_filter_handles_off() {
        let filter = build_filter("off", "info");
        assert_eq!(format!("{filter}"), "off");
    }

    #[test]
    fn build_filter_handles_trace() {
        let filter = build_filter("trace", "info");
        assert_eq!(format!("{filter}"), "trace");
    }

    // ── prepare_file_appender tests ─────────────────────────────

    #[test]
    fn prepare_file_appender_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("subdir").join("test.log");

        let result = prepare_file_appender(log_path.to_str().unwrap());
        assert!(
            result.is_ok(),
            "Should create subdirectory and return appender"
        );
        assert!(
            dir.path().join("subdir").exists(),
            "Subdirectory should exist"
        );
    }

    #[test]
    fn prepare_file_appender_handles_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        let result = prepare_file_appender(log_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn prepare_file_appender_fails_on_invalid_path() {
        // /dev/null/impossible is not a valid directory on any OS
        let result = prepare_file_appender("/dev/null/impossible/test.log");
        assert!(
            result.is_err(),
            "Should fail when directory can't be created"
        );
    }

    // ── LogGuard tests ──────────────────────────────────────────

    #[test]
    fn log_guard_without_file_has_no_worker() {
        let guard = LogGuard { _guard: None };
        assert!(guard._guard.is_none());
    }

    // ── Audit path resolution (CKSPEC-OUT-004) ──────────────────

    #[test]
    fn audit_base_config_uses_config_home() {
        let base = audit_base_in(
            "config",
            "myapp",
            PathBuf::from("/home/u/.config"),
            Some(PathBuf::from("/home/u/.local/share")),
        );
        assert_eq!(base, PathBuf::from("/home/u/.config/myapp"));
    }

    #[test]
    fn audit_base_platform_uses_the_native_data_dir() {
        let base = audit_base_in(
            "platform",
            "myapp",
            PathBuf::from("/Users/u/.config"),
            Some(PathBuf::from("/Users/u/Library/Application Support")),
        );
        assert_eq!(
            base,
            PathBuf::from("/Users/u/Library/Application Support/myapp")
        );
    }

    #[test]
    fn audit_base_platform_falls_back_to_config_home_without_a_data_dir() {
        let base = audit_base_in("platform", "myapp", PathBuf::from("/c"), None);
        assert_eq!(base, PathBuf::from("/c/myapp"));
    }

    #[test]
    fn audit_base_unknown_location_defaults_to_config() {
        let base = audit_base_in(
            "bogus",
            "myapp",
            PathBuf::from("/c"),
            Some(PathBuf::from("/d")),
        );
        assert_eq!(base, PathBuf::from("/c/myapp"));
    }

    #[test]
    fn resolve_audit_path_honors_an_absolute_path_verbatim() {
        let p = resolve_audit_path("/var/log/app.log", "config", "myapp");
        assert_eq!(p, PathBuf::from("/var/log/app.log"));
    }

    // config_home resolution is tested purely (env injected) so these never
    // mutate process-global env — which would race under parallel test threads.

    #[test]
    fn config_home_prefers_xdg_when_set() {
        let p = config_home_from(Some(PathBuf::from("/x")), Some(PathBuf::from("/home/u")));
        assert_eq!(p, PathBuf::from("/x"));
    }

    #[test]
    fn config_home_falls_back_to_home_dotconfig() {
        let p = config_home_from(None, Some(PathBuf::from("/home/u")));
        assert_eq!(p, PathBuf::from("/home/u/.config"));
    }

    #[test]
    fn config_home_last_resort_is_relative_dotconfig() {
        let p = config_home_from(None, None);
        assert_eq!(p, PathBuf::from(".config"));
    }
}

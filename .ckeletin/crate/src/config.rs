use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

/// Application configuration.
///
/// Loaded with layered precedence: defaults < config file < env vars.
/// CLI flag overrides are applied by the cli crate after loading.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Console log level (trace, debug, info, warn, error).
    #[serde(default = "defaults::log_level")]
    pub log_level: String,

    /// Enable file logging (audit stream). On by default (CKSPEC-OUT-004:
    /// the audit stream is always active unless explicitly disabled).
    #[serde(default = "defaults::log_file_enabled")]
    pub log_file_enabled: bool,

    /// Path to the log file.
    #[serde(default = "defaults::log_file_path")]
    pub log_file_path: String,

    /// File log level.
    #[serde(default = "defaults::log_file_level")]
    pub log_file_level: String,

    /// Where the audit log lives when `log_file_path` is relative:
    /// "config" → ~/.config/<app> (default, XDG-style on every platform),
    /// "platform" → the OS-native app-data dir (e.g. ~/Library/Application
    /// Support/<app> on macOS). An absolute `log_file_path` overrides this.
    #[serde(default = "defaults::log_location")]
    pub log_location: String,

    /// Enable JSON output mode globally.
    #[serde(default)]
    pub json: bool,
}

mod defaults {
    pub fn log_level() -> String {
        "info".to_string()
    }
    pub fn log_file_enabled() -> bool {
        true
    }
    pub fn log_file_path() -> String {
        "logs/app.log".to_string()
    }
    pub fn log_file_level() -> String {
        "debug".to_string()
    }
    pub fn log_location() -> String {
        "config".to_string()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: defaults::log_level(),
            log_file_enabled: defaults::log_file_enabled(),
            log_file_path: defaults::log_file_path(),
            log_file_level: defaults::log_file_level(),
            log_location: defaults::log_location(),
            json: false,
        }
    }
}

impl Config {
    /// Load configuration with layered precedence:
    /// defaults → config file (if exists) → environment variables.
    ///
    /// `env_prefix` controls which environment variables are read.
    /// Projects pass their own name: `"WORKHORSE_"`, `"MYAPP_"`.
    /// The scaffold default is `"CKELETIN_"`.
    ///
    /// Missing config file is not an error — defaults apply.
    pub fn load(
        config_path: Option<&str>,
        env_prefix: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut figment = Figment::new().merge(Serialized::defaults(Config::default()));

        if let Some(path) = config_path {
            // Explicit --config: file MUST exist. Silent fallback is misleading.
            if !std::path::Path::new(path).exists() {
                return Err(format!("config file not found: {path}").into());
            }
            figment = figment.merge(Toml::file(path));
        } else {
            // Default location — missing file is silently ignored
            figment = figment.merge(Toml::file("config.toml"));
        }

        figment
            .merge(Env::prefixed(env_prefix))
            .extract()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const TEST_PREFIX: &str = "CKTEST_";

    #[test]
    fn default_config_values() {
        let config = Config::default();
        assert_eq!(config.log_level, "info");
        assert!(config.log_file_enabled, "audit log is on by default");
        assert_eq!(config.log_file_path, "logs/app.log");
        assert_eq!(config.log_file_level, "debug");
        assert_eq!(config.log_location, "config");
        assert!(!config.json);
    }

    #[test]
    fn load_returns_defaults_when_no_file() {
        let config = Config::load(None, TEST_PREFIX).unwrap();
        assert_eq!(config.log_level, "info");
        assert!(!config.json);
    }

    #[test]
    fn load_reads_toml_file() {
        let mut file = NamedTempFile::with_suffix(".toml").unwrap();
        writeln!(file, "log_level = \"debug\"\njson = true").unwrap();
        let config = Config::load(Some(file.path().to_str().unwrap()), TEST_PREFIX).unwrap();
        assert_eq!(config.log_level, "debug");
        assert!(config.json);
    }

    #[test]
    fn toml_overrides_only_specified_values() {
        // Audit logging defaults to on; a TOML value can turn it off without
        // disturbing the other defaults.
        let mut file = NamedTempFile::with_suffix(".toml").unwrap();
        writeln!(file, "log_file_enabled = false").unwrap();
        let config = Config::load(Some(file.path().to_str().unwrap()), TEST_PREFIX).unwrap();
        assert!(!config.log_file_enabled);
        assert_eq!(config.log_level, "info");
        assert!(!config.json);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let mut file = NamedTempFile::with_suffix(".toml").unwrap();
        writeln!(file, "not valid toml [[[").unwrap();
        let result = Config::load(Some(file.path().to_str().unwrap()), TEST_PREFIX);
        assert!(result.is_err());
    }

    #[test]
    fn explicit_missing_file_returns_error() {
        let result = Config::load(Some("/nonexistent/config.toml"), TEST_PREFIX);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "Error should mention file not found: {err}"
        );
    }

    #[test]
    fn env_prefix_is_respected() {
        // Use a unique prefix to avoid interference with other tests
        let prefix = "CKROBUST_";
        std::env::set_var("CKROBUST_LOG_LEVEL", "trace");
        let config = Config::load(None, prefix).unwrap();
        assert_eq!(config.log_level, "trace");
        std::env::remove_var("CKROBUST_LOG_LEVEL");
    }

    #[test]
    fn different_prefix_ignores_other_env_vars() {
        std::env::set_var("WRONGPREFIX_LOG_LEVEL", "error");
        let config = Config::load(None, "RIGHTPREFIX_").unwrap();
        assert_eq!(config.log_level, "info");
        std::env::remove_var("WRONGPREFIX_LOG_LEVEL");
    }

    /// Every config field must be settable via env var.
    /// This catches the .split("_") bug that silently broke env overrides.
    #[test]
    fn every_config_field_settable_via_env() {
        let prefix = "CKEVERY_";
        std::env::set_var("CKEVERY_LOG_LEVEL", "error");
        std::env::set_var("CKEVERY_LOG_FILE_ENABLED", "true");
        std::env::set_var("CKEVERY_LOG_FILE_PATH", "/tmp/test.log");
        std::env::set_var("CKEVERY_LOG_FILE_LEVEL", "trace");
        std::env::set_var("CKEVERY_LOG_LOCATION", "platform");
        std::env::set_var("CKEVERY_JSON", "true");

        let config = Config::load(None, prefix).unwrap();
        assert_eq!(config.log_level, "error", "LOG_LEVEL env not applied");
        assert!(config.log_file_enabled, "LOG_FILE_ENABLED env not applied");
        assert_eq!(
            config.log_file_path, "/tmp/test.log",
            "LOG_FILE_PATH env not applied"
        );
        assert_eq!(
            config.log_file_level, "trace",
            "LOG_FILE_LEVEL env not applied"
        );
        assert_eq!(
            config.log_location, "platform",
            "LOG_LOCATION env not applied"
        );
        assert!(config.json, "JSON env not applied");

        std::env::remove_var("CKEVERY_LOG_LEVEL");
        std::env::remove_var("CKEVERY_LOG_FILE_ENABLED");
        std::env::remove_var("CKEVERY_LOG_FILE_PATH");
        std::env::remove_var("CKEVERY_LOG_FILE_LEVEL");
        std::env::remove_var("CKEVERY_LOG_LOCATION");
        std::env::remove_var("CKEVERY_JSON");
    }

    /// Env vars override TOML file values (precedence: default < file < env).
    #[test]
    fn env_overrides_toml_file() {
        let prefix = "CKPREC_";
        let mut file = NamedTempFile::with_suffix(".toml").unwrap();
        writeln!(file, "log_level = \"debug\"").unwrap();
        std::env::set_var("CKPREC_LOG_LEVEL", "error");

        let config = Config::load(Some(file.path().to_str().unwrap()), prefix).unwrap();
        assert_eq!(config.log_level, "error", "env should override TOML");

        std::env::remove_var("CKPREC_LOG_LEVEL");
    }
}

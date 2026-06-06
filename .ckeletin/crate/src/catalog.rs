//! Machine-readable command catalog (CKSPEC-AGENT-006).
//!
//! These types ARE the catalog schema — emitting them as the `data` of an
//! OUT-002 success envelope is how a ckeletin CLI self-reports its command
//! surface as structured data, so an agent discovers capabilities without
//! parsing human `--help` text or trusting hand-written AGENTS.md prose.
//!
//! The schema is the cross-implementation contract agreed with ckeletin-go on
//! the spec issue: a **required core** every implementation derives losslessly
//! (so one parser works across both), plus **optional** fields each emits where
//! its CLI framework exposes them (omitted, never hand-filled).
//!
//! Required core:
//!   - command: `name`, `description`, `flags`, `commands` (recursive)
//!   - flag: `long`, `required`, `takes_value`
//!   - top level: `name`, `description`, `global_flags` (listed once), `commands`
//!
//! Optional (this impl fills what clap derives): flag `short`, `description`,
//! `default`, `possible_values`.
//!
//! Defining the types in the framework crate (not the cli crate) makes the
//! schema a single shared Rust type: a derived project literally cannot emit a
//! wrong-shaped catalog. The clap → `Catalog` walk lives in the cli crate
//! (clap is cli-only), which is the only implementation-specific part.

use serde::Serialize;
use std::fmt;

/// A single flag in the catalog.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CatalogFlag {
    /// Long form, without `--` (required core).
    pub long: String,
    /// Whether the flag must be supplied (required core).
    pub required: bool,
    /// Whether the flag consumes a value (`--x value`) vs. a boolean switch
    /// (required core; the normalized intersection both clap and cobra derive).
    pub takes_value: bool,
    /// Short form, without `-` (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    /// Help text (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Default value, if any (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Allowed values for enumerated flags, e.g. `--output text|json` (optional).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub possible_values: Vec<String>,
}

/// A command and its subcommands.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CatalogCommand {
    pub name: String,
    pub description: String,
    pub flags: Vec<CatalogFlag>,
    pub commands: Vec<CatalogCommand>,
}

/// The whole command surface of a CLI.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Catalog {
    pub name: String,
    pub description: String,
    /// Flags that apply to every command, listed once here (not duplicated into
    /// each command's `flags`).
    pub global_flags: Vec<CatalogFlag>,
    pub commands: Vec<CatalogCommand>,
}

fn fmt_flag(f: &mut fmt::Formatter<'_>, flag: &CatalogFlag) -> fmt::Result {
    let value = if flag.takes_value { " <value>" } else { "" };
    let desc = flag
        .description
        .as_deref()
        .map(|d| format!("  {d}"))
        .unwrap_or_default();
    writeln!(f, "  --{}{}{}", flag.long, value, desc)
}

impl fmt::Display for Catalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} — {}", self.name, self.description)?;
        if !self.global_flags.is_empty() {
            writeln!(f, "\nGlobal flags:")?;
            for flag in &self.global_flags {
                fmt_flag(f, flag)?;
            }
        }
        writeln!(f, "\nCommands:")?;
        for cmd in &self.commands {
            writeln!(f, "  {:<12} {}", cmd.name, cmd.description)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Catalog {
        Catalog {
            name: "demo".into(),
            description: "A demo CLI".into(),
            global_flags: vec![CatalogFlag {
                long: "output".into(),
                required: false,
                takes_value: true,
                short: None,
                description: Some("Output format".into()),
                default: Some("text".into()),
                possible_values: vec!["text".into(), "json".into()],
            }],
            commands: vec![CatalogCommand {
                name: "ping".into(),
                description: "Check connectivity".into(),
                flags: vec![],
                commands: vec![],
            }],
        }
    }

    #[test]
    fn serializes_required_core_and_skips_empty_optionals() {
        let json = serde_json::to_value(sample()).unwrap();
        assert_eq!(json["name"], "demo");
        assert_eq!(json["global_flags"][0]["long"], "output");
        assert_eq!(json["global_flags"][0]["takes_value"], true);
        assert_eq!(json["global_flags"][0]["possible_values"][1], "json");
        assert_eq!(json["commands"][0]["name"], "ping");
        // A flag with no short/possible_values omits them rather than emitting null/[].
        let bare = serde_json::to_value(CatalogFlag {
            long: "verbose".into(),
            required: false,
            takes_value: false,
            short: None,
            description: None,
            default: None,
            possible_values: vec![],
        })
        .unwrap();
        assert!(bare.get("short").is_none());
        assert!(bare.get("possible_values").is_none());
        assert_eq!(bare["takes_value"], false);
    }

    #[test]
    fn display_lists_commands_and_global_flags() {
        let out = format!("{}", sample());
        assert!(out.contains("Commands:"));
        assert!(out.contains("ping"));
        assert!(out.contains("--output <value>"));
    }
}

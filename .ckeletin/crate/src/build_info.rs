//! Build identity — the git provenance baked into the binary at compile time,
//! surfaced in `--version` (and a `version` command) so an operator or agent can
//! tell exactly which commit produced a given binary.
//!
//! This module is the generic, prefix-agnostic FRAMEWORK primitive: the
//! [`BuildInfo`] type and its rendering. It deliberately does NOT name the
//! compile-time env vars the values come from — those belong to the adopter, who
//! both SETS them (in their build script) and READS them (at their call site).
//! The scaffold's worked example shows both halves un-hidden: `crates/cli/build.rs`
//! bakes the identity and `crates/cli/src/version.rs` wires it into a [`BuildInfo`].
//!
//! Cross-implementation note: this mirrors ckeletin-go's `--version` provenance
//! (version + commit + date + dirty). Runtime *staleness* checking — comparing
//! the baked commit to the repo's current HEAD — is deliberately OUT of scope:
//! it is an adopter-specific policy, not part of the shared build-identity
//! contract (ckeletin-go keeps its equivalent in a separate `doctor` command).

use serde::Serialize;
use std::fmt;

/// Placeholder for a field that could not be resolved at build time — an honest
/// "we don't know", never a fabricated value.
pub const UNKNOWN: &str = "unknown";

/// Build identity baked into the binary at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildInfo {
    /// Semantic version (from `CARGO_PKG_VERSION`).
    pub version: String,
    /// Short git commit identity the binary was built from, or [`UNKNOWN`].
    pub commit: String,
    /// Commit date (`git %cs`, `YYYY-MM-DD`), rendered after the word
    /// "built" in [`version_line`](BuildInfo::version_line); or [`UNKNOWN`].
    pub date: String,
    /// Whether the working tree had uncommitted TRACKED changes at build time.
    /// Only meaningful when `commit != UNKNOWN`: the producer must derive both
    /// from one atomic git read so cleanliness is never claimed for an unknown
    /// commit (see the scaffold's `version::split_commit_dirty`).
    pub dirty: bool,
}

impl BuildInfo {
    /// Construct from already-resolved values. The adopter reads the baked env at
    /// their own call site (so `env!`/`option_env!` resolve in their crate) and
    /// hands the values here — see `crates/cli/src/version.rs`. This is a
    /// convenience constructor for display-only provenance; it performs NO
    /// validation — honest inputs are the producer's responsibility.
    pub fn new(
        version: impl Into<String>,
        commit: impl Into<String>,
        date: impl Into<String>,
        dirty: bool,
    ) -> Self {
        Self {
            version: version.into(),
            commit: commit.into(),
            date: date.into(),
            dirty,
        }
    }

    /// One-line version string: `"<version>, commit <commit>, built <date>"`,
    /// with `" (dirty)"` appended when built from an uncommitted tree. Mirrors
    /// ckeletin-go's `--version` rendering.
    pub fn version_line(&self) -> String {
        let dirty = if self.dirty { " (dirty)" } else { "" };
        format!(
            "{}, commit {}, built {}{}",
            self.version, self.commit, self.date, dirty
        )
    }
}

impl fmt::Display for BuildInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version_line())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_line_clean() {
        let info = BuildInfo::new("0.1.0", "abc1234", "2026-06-03", false);
        assert_eq!(
            info.version_line(),
            "0.1.0, commit abc1234, built 2026-06-03"
        );
    }

    #[test]
    fn version_line_dirty_appends_marker() {
        let info = BuildInfo::new("0.1.0", "abc1234", "2026-06-03", true);
        assert_eq!(
            info.version_line(),
            "0.1.0, commit abc1234, built 2026-06-03 (dirty)"
        );
    }

    #[test]
    fn display_matches_version_line() {
        let info = BuildInfo::new("0.1.0", "abc1234", "2026-06-03", false);
        assert_eq!(format!("{info}"), info.version_line());
    }

    #[test]
    fn version_line_renders_unknown_fields_honestly() {
        // The honest-degradation path: when git can't resolve, UNKNOWN must flow
        // through verbatim — never dropped or special-cased into a real-looking line.
        let info = BuildInfo::new("0.1.0", UNKNOWN, UNKNOWN, false);
        assert_eq!(info.version_line(), "0.1.0, commit unknown, built unknown");
    }

    #[test]
    fn serializes_all_fields() {
        let info = BuildInfo::new("0.1.0", "abc1234", "2026-06-03", true);
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["version"], "0.1.0");
        assert_eq!(json["commit"], "abc1234");
        assert_eq!(json["date"], "2026-06-03");
        assert_eq!(json["dirty"], true);
    }
}

use regex::Regex;
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

/// Error type for ruleset loading.
#[derive(Debug, Error)]
pub enum RulesetError {
    #[error("failed to read ruleset file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse ruleset TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("failed to compile regex for rule '{id}': {error}")]
    Regex { id: String, error: regex::Error },
}

/// A single rule definition as read from TOML.
#[derive(Debug, Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub direction: String,
    pub pattern: String,
    pub description: String,
    #[serde(default)]
    pub luhn_validate: bool,
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// "regex" (default) or "builtin" (detection handled by Rust code).
    #[serde(default = "default_detect_mode")]
    pub detect_mode: String,
}

fn default_detect_mode() -> String {
    "regex".to_string()
}

/// Container for TOML deserialization (the file has a `[[rules]]` array).
#[derive(Debug, Deserialize)]
struct RulesetFile {
    rules: Vec<RuleDefinition>,
}

/// A compiled rule: the definition with an optional pre-compiled regex.
/// Builtin rules have `regex = None`; regex-driven rules have `regex = Some(...)`.
#[derive(Debug)]
pub struct CompiledRule {
    pub definition: RuleDefinition,
    pub regex: Option<Regex>,
}

/// A loaded and compiled ruleset.
#[derive(Debug)]
pub struct Ruleset {
    pub rules: Vec<CompiledRule>,
}

impl Ruleset {
    /// Load rules from all `*.toml` files in the given directory.
    pub fn load_from_dir(path: &Path) -> Result<Self, RulesetError> {
        let mut rules = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();
            if file_path.extension().map(|e| e == "toml").unwrap_or(false) {
                let content = std::fs::read_to_string(&file_path)?;
                let rule_file: RulesetFile = toml::from_str(&content)?;
                for def in rule_file.rules {
                    let regex = if def.detect_mode == "builtin" {
                        None
                    } else {
                        Some(Regex::new(&def.pattern).map_err(|e| RulesetError::Regex {
                            id: def.id.clone(),
                            error: e,
                        })?)
                    };
                    rules.push(CompiledRule {
                        definition: def,
                        regex,
                    });
                }
            }
        }
        Ok(Self { rules })
    }

    /// Load the default rules embedded at compile time.
    pub fn default_rules() -> Result<Self, RulesetError> {
        // Embed all rule files at compile time so the binary is self-contained.
        const SECRET_TOML: &str = include_str!("../../../rules/secret.toml");
        const UNICODE_TAGS_TOML: &str = include_str!("../../../rules/unicode_tags.toml");
        const ZERO_WIDTH_TOML: &str = include_str!("../../../rules/zero_width.toml");
        const BIDI_TOML: &str = include_str!("../../../rules/bidi.toml");
        const HOMOGLYPH_TOML: &str = include_str!("../../../rules/homoglyph.toml");
        const SPECIAL_TOKEN_TOML: &str = include_str!("../../../rules/special_token.toml");

        let toml_sources = [
            SECRET_TOML,
            UNICODE_TAGS_TOML,
            ZERO_WIDTH_TOML,
            BIDI_TOML,
            HOMOGLYPH_TOML,
            SPECIAL_TOKEN_TOML,
        ];
        let mut rules = Vec::new();

        for source in &toml_sources {
            let rule_file: RulesetFile = toml::from_str(source)?;
            for def in rule_file.rules {
                let regex = if def.detect_mode == "builtin" {
                    None
                } else {
                    Some(Regex::new(&def.pattern).map_err(|e| RulesetError::Regex {
                        id: def.id.clone(),
                        error: e,
                    })?)
                };
                rules.push(CompiledRule {
                    definition: def,
                    regex,
                });
            }
        }

        Ok(Self { rules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_loads_correctly() {
        let ruleset = Ruleset::default_rules().expect("default rules must load");
        // 16 secret + 2 unicode_tags + 6 zero_width + 1 bidi + 1 homoglyph + 3 special_token = 29
        // (8 original secret rules + 8 new: slack_token, gcp_api_key, google_oauth_secret,
        //  npm_access_token, sendgrid_api_key, stripe_webhook_secret, gitlab_pat,
        //  gitlab_runner_auth_token)
        assert_eq!(ruleset.rules.len(), 29, "expected 29 rules total");
    }

    #[test]
    fn default_rules_have_correct_ids() {
        let ruleset = Ruleset::default_rules().expect("default rules must load");
        let ids: Vec<&str> = ruleset
            .rules
            .iter()
            .map(|r| r.definition.id.as_str())
            .collect();
        // Secret rules
        assert!(ids.contains(&"secret.anthropic_key"));
        assert!(ids.contains(&"secret.openai_key"));
        assert!(ids.contains(&"secret.aws_access_key"));
        assert!(ids.contains(&"secret.github_pat"));
        assert!(ids.contains(&"secret.stripe_live_key"));
        assert!(ids.contains(&"secret.pem_private_key"));
        assert!(ids.contains(&"secret.card_pan"));
        assert!(ids.contains(&"secret.github_fine_grained_pat"));
        // Unicode tags rules
        assert!(ids.contains(&"unicode_tags.tag_block"));
        assert!(ids.contains(&"unicode_tags.surrogate"));
        // Zero width rules
        assert!(ids.contains(&"zero_width.zwsp"));
        assert!(ids.contains(&"zero_width.zwnj"));
        assert!(ids.contains(&"zero_width.zwj"));
        assert!(ids.contains(&"zero_width.bom"));
        assert!(ids.contains(&"zero_width.soft_hyphen"));
        // Bidi rules
        assert!(ids.contains(&"bidi.control_char"));
        // Homoglyph rules
        assert!(ids.contains(&"homoglyph.mixed_script_confusable"));
        // Special token rules
        assert!(ids.contains(&"special_token.chatml"));
        assert!(ids.contains(&"special_token.inst_marker"));
        assert!(ids.contains(&"special_token.turn_marker"));
    }

    #[test]
    fn all_regexes_compile() {
        let ruleset = Ruleset::default_rules().expect("default rules must load");
        // The act of loading already compiles — just assert we have rules.
        assert!(!ruleset.rules.is_empty());
    }

    #[test]
    fn builtin_rules_have_no_regex() {
        let ruleset = Ruleset::default_rules().expect("default rules must load");
        for rule in &ruleset.rules {
            if rule.definition.detect_mode == "builtin" {
                assert!(
                    rule.regex.is_none(),
                    "builtin rule '{}' should have no regex",
                    rule.definition.id
                );
            } else {
                assert!(
                    rule.regex.is_some(),
                    "regex rule '{}' should have a compiled regex",
                    rule.definition.id
                );
            }
        }
    }
}

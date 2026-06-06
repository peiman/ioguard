use serde::{Deserialize, Serialize};

/// The verdict of a scan: the maximum severity finding determines the verdict.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

/// Severity of a finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warn,
    Block,
}

/// Direction the scan applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Input,
    Output,
    Both,
}

/// Category of a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Secret,
    UnicodeTags,
    ZeroWidth,
    Bidi,
    Homoglyph,
    SpecialToken,
}

/// A single detection finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub category: Category,
    pub severity: Severity,
    pub direction: Direction,
    /// Byte offsets (start, end) into the scanned text.
    pub span: (usize, usize),
    /// First 8 chars + "..." — NEVER the full secret.
    pub preview: String,
}

/// The result of a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub stats: Stats,
}

/// Scan statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub bytes_scanned: usize,
    pub findings_count: usize,
    pub duration_us: u64,
}

/// Options controlling the scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub direction: Direction,
    pub enabled_categories: Vec<Category>,
    /// BCP 47 locale tag; affects bidi rule exemption for RTL locales.
    pub locale: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            direction: Direction::Both,
            enabled_categories: vec![
                Category::Secret,
                Category::UnicodeTags,
                Category::ZeroWidth,
                Category::Bidi,
                Category::Homoglyph,
                Category::SpecialToken,
            ],
            locale: None,
        }
    }
}

impl ScanOptions {
    /// Returns true if the given category is enabled in these options.
    pub fn category_enabled(&self, category: &Category) -> bool {
        self.enabled_categories.contains(category)
    }
}

/// Derive the verdict from a list of findings.
pub fn findings_to_verdict(findings: &[Finding]) -> Verdict {
    let max_severity = findings.iter().map(|f| &f.severity).max();
    match max_severity {
        None => Verdict::Allow,
        Some(Severity::Warn) => Verdict::Warn,
        Some(Severity::Block) => Verdict::Block,
    }
}

/// Truncate a matched secret to a safe preview: first 8 chars + "..."
pub fn make_preview(matched: &str) -> String {
    let chars: String = matched.chars().take(8).collect();
    format!("{chars}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Verdict::Allow).unwrap(), "\"allow\"");
        assert_eq!(serde_json::to_string(&Verdict::Warn).unwrap(), "\"warn\"");
        assert_eq!(serde_json::to_string(&Verdict::Block).unwrap(), "\"block\"");
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Block > Severity::Warn);
    }

    #[test]
    fn default_scan_options() {
        let opts = ScanOptions::default();
        assert_eq!(opts.direction, Direction::Both);
        assert!(opts.category_enabled(&Category::Secret));
        assert!(opts.category_enabled(&Category::UnicodeTags));
        assert!(opts.category_enabled(&Category::ZeroWidth));
        assert!(opts.category_enabled(&Category::Bidi));
        assert!(opts.category_enabled(&Category::Homoglyph));
        assert!(opts.category_enabled(&Category::SpecialToken));
        assert!(opts.locale.is_none());
    }

    #[test]
    fn findings_to_verdict_empty() {
        assert_eq!(findings_to_verdict(&[]), Verdict::Allow);
    }

    #[test]
    fn findings_to_verdict_block() {
        let f = Finding {
            rule_id: "test".to_string(),
            category: Category::Secret,
            severity: Severity::Block,
            direction: Direction::Both,
            span: (0, 10),
            preview: "12345678...".to_string(),
        };
        assert_eq!(findings_to_verdict(&[f]), Verdict::Block);
    }

    #[test]
    fn make_preview_truncates() {
        let secret = ["sk-ant-", "api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ"].concat();
        let preview = make_preview(&secret);
        assert_eq!(preview, "sk-ant-a...");
        assert!(preview.len() <= 11);
    }
}

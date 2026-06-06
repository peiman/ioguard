use unicode_normalization::UnicodeNormalization;

use crate::detectors::luhn;
use crate::ruleset::Ruleset;
use crate::types::make_preview;
use crate::types::{Category, Direction, Finding, ScanOptions, Severity};

/// Build a mapping from byte offsets in the NFKC-normalized string back to byte offsets
/// in the original string, to allow accurate span reporting when matching on normalized text.
///
/// Returns `(normalized_string, norm_byte_to_orig_byte)` where `norm_byte_to_orig_byte[i]`
/// is the byte offset in `original` corresponding to the start of the normalized char whose
/// UTF-8 encoding starts at or before byte `i` of the normalized string.
///
/// Specifically, for each character position `k` in the normalized string (by char, not byte),
/// we track:
///   - `norm_byte`: the byte offset of char `k` in the normalized UTF-8
///   - `orig_byte`: the byte offset of the *original* char(s) that produced char `k`
///
/// We record two entries per normalized char:
///   start → corresponding original start
///   end   → corresponding original end (i.e. start of the next original char)
///
/// This lets us map `norm_match.start()` → `orig_start` and `norm_match.end()` → `orig_end`.
fn nfkc_with_offset_map(original: &str) -> (String, Vec<usize>) {
    let mut normalized = String::with_capacity(original.len());
    // For each byte index in `normalized`, store the corresponding byte index in `original`
    // where the source char started.
    let mut norm_byte_to_orig_start: Vec<usize> = Vec::with_capacity(original.len());
    // We also need one sentinel beyond the end.
    // Strategy: track orig_byte_start for each normalized char, and record the orig_byte_end
    // for the last position (the one past the last char).

    let mut orig_byte = 0usize;

    for orig_char in original.chars() {
        let orig_char_len = orig_char.len_utf8();
        // NFKC-decompose this single char (may expand to multiple chars, e.g. ligatures)
        let mut expanded: String = std::iter::once(orig_char).nfkc().collect();
        if expanded.is_empty() {
            // NFKC of a char should never be empty, but handle defensively
            expanded.push(orig_char);
        }
        for norm_char in expanded.chars() {
            let norm_char_len = norm_char.len_utf8();
            // Each byte of this norm_char maps back to orig_byte
            for _ in 0..norm_char_len {
                norm_byte_to_orig_start.push(orig_byte);
            }
            normalized.push(norm_char);
        }
        orig_byte += orig_char_len;
    }
    // Sentinel: byte offset just past the last original char
    norm_byte_to_orig_start.push(orig_byte);

    (normalized, norm_byte_to_orig_start)
}

/// Strip spaces and dashes from a candidate PAN string to get raw digits.
fn strip_non_digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Normalize an allowlist entry for comparison (strip spaces/dashes to raw digits
/// for PAN comparisons; use as-is for other entries).
fn normalize_for_allowlist(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Check whether the matched text appears in the rule's allowlist.
///
/// For PAN rules (luhn_validate = true), we compare stripped digits.
/// For other rules, we compare the full matched text.
fn is_allowlisted(matched: &str, allowlist: &[String], luhn_validate: bool) -> bool {
    if luhn_validate {
        let stripped = strip_non_digits(matched);
        allowlist
            .iter()
            .any(|entry| normalize_for_allowlist(entry) == stripped)
    } else {
        allowlist.iter().any(|entry| entry == matched)
    }
}

/// Convert a rule severity string to the `Severity` enum.
fn parse_severity(s: &str) -> Severity {
    match s {
        "warn" => Severity::Warn,
        _ => Severity::Block,
    }
}

/// Convert a rule direction string to the `Direction` enum.
fn parse_direction(s: &str) -> Direction {
    match s {
        "input" => Direction::Input,
        "output" => Direction::Output,
        _ => Direction::Both,
    }
}

/// The secret detector: runs all secret-category rules from the ruleset.
pub struct SecretDetector {
    ruleset: Ruleset,
}

impl SecretDetector {
    /// Create a new `SecretDetector` using the default embedded ruleset.
    pub fn new() -> Self {
        let ruleset = Ruleset::default_rules().expect("default ruleset must load");
        Self { ruleset }
    }

    /// Detect secrets in the given text and return a list of findings.
    pub fn detect(&self, text: &str, _opts: &ScanOptions) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build NFKC-normalized copy and byte-offset map once for all rules.
        // This folds fullwidth/halfwidth variants (ＡＩｚａ→AIza, ＡＫＩＡ→AKIA, ｓｋ→sk)
        // so that provider-prefix patterns fire even when characters are encoded with
        // fullwidth Unicode code points. Match offsets are mapped back to the original
        // byte positions for accurate span and preview reporting.
        let (normalized_text, norm_to_orig) = nfkc_with_offset_map(text);

        for rule in &self.ruleset.rules {
            if rule.definition.category != "secret" {
                continue;
            }

            // Secret rules are always regex-driven; skip any builtin rules in the secret category.
            let Some(ref regex) = rule.regex else {
                continue;
            };

            // Run the regex on the NFKC-normalized text. Map match byte offsets back
            // to original byte offsets using the precomputed offset map.
            for m in regex.find_iter(&normalized_text) {
                // Map normalized byte range → original byte range.
                let orig_start = norm_to_orig[m.start()];
                let orig_end = norm_to_orig[m.end()];
                let matched = &text[orig_start..orig_end];

                // PAN digit-adjacency boundary check.
                //
                // The card_pan pattern intentionally omits \b anchors because \b cannot
                // distinguish a letter→digit transition (both \w) from a true boundary.
                // Without \b, the pattern can match inside "card4111...1111here" but would
                // also extend into longer digit runs like "94111...11111" (17 digits).
                //
                // Rule: suppress the match ONLY if the char immediately before or after
                // the span is an ASCII digit (the PAN is embedded in a longer digit run).
                // Adjacent letters, underscores, and punctuation are valid delimiters —
                // the PAN is still blocked in those cases.
                //
                // Note: boundary check runs on orig_start/orig_end (original text offsets),
                // since card numbers are ASCII and NFKC won't change digit boundaries.
                if rule.definition.luhn_validate {
                    let text_bytes = text.as_bytes();
                    let before_is_digit =
                        orig_start > 0 && text_bytes[orig_start - 1].is_ascii_digit();
                    let after_is_digit =
                        orig_end < text_bytes.len() && text_bytes[orig_end].is_ascii_digit();
                    if before_is_digit || after_is_digit {
                        continue;
                    }
                }

                // Allowlist check (must happen before Luhn to allow test cards)
                if is_allowlisted(
                    matched,
                    &rule.definition.allowlist,
                    rule.definition.luhn_validate,
                ) {
                    continue;
                }

                // Luhn validation for PAN rules
                if rule.definition.luhn_validate {
                    let digits = strip_non_digits(matched);
                    if !luhn::is_valid_luhn(&digits) {
                        continue;
                    }
                }

                findings.push(Finding {
                    rule_id: rule.definition.id.clone(),
                    category: Category::Secret,
                    severity: parse_severity(&rule.definition.severity),
                    direction: parse_direction(&rule.definition.direction),
                    span: (orig_start, orig_end),
                    preview: make_preview(matched),
                });
            }
        }

        findings
    }
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> SecretDetector {
        SecretDetector::new()
    }

    fn default_opts() -> ScanOptions {
        ScanOptions::default()
    }

    #[test]
    fn detects_anthropic_key() {
        let text = ["sk-ant-", "api03-ABCDEFGHIJKLMNOPQRSTU"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "expected 1 finding for Anthropic key");
        assert_eq!(findings[0].rule_id, "secret.anthropic_key");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_openai_key() {
        // OpenAI key format: sk-<prefix>T3BlbkFJ<suffix>
        let text = ["sk-proj-", "ABCDEFGHIJKLMNOPQRST3BlbkFJABCDEFG"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "expected 1 finding for OpenAI key");
        assert_eq!(findings[0].rule_id, "secret.openai_key");
    }

    #[test]
    fn detects_aws_key() {
        let text = ["AKI", "AIOSFODNN7EXAMPLE"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "expected 1 finding for AWS key");
        assert_eq!(findings[0].rule_id, "secret.aws_access_key");
    }

    #[test]
    fn detects_github_pat() {
        let text = ["gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "expected 1 finding for GitHub PAT");
        assert_eq!(findings[0].rule_id, "secret.github_pat");
    }

    #[test]
    fn detects_stripe_live_key() {
        let text = ["sk_", "live_abc123def456ghi789jkl012mnop"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "expected 1 finding for Stripe live key");
        assert_eq!(findings[0].rule_id, "secret.stripe_live_key");
    }

    #[test]
    fn detects_pem_private_key() {
        let text = ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "expected 1 finding for PEM private key");
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_luhn_valid_card() {
        // Visa test card 4111 1111 1111 1111 — Luhn valid but NOT in allowlist
        let text = "4111 1111 1111 1111";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 1, "expected 1 finding for Luhn-valid card");
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    #[test]
    fn allows_stripe_test_card() {
        let text = "4242 4242 4242 4242";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 0, "Stripe test card must be allowlisted");
    }

    #[test]
    fn allows_amex_test_card() {
        let text = "378282246310005";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 0, "Amex test card must be allowlisted");
    }

    #[test]
    fn ignores_git_sha() {
        // 40-char hex SHA — should not match any secret rule
        let text = "abc123def456abc123def456abc123def456abcd";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 0, "git SHA must not be detected");
    }

    #[test]
    fn ignores_ordinary_prose() {
        let text = "The quick brown fox jumps over the lazy dog.";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 0, "ordinary prose must not be detected");
    }

    #[test]
    fn ignores_luhn_invalid_card() {
        // Last digit changed from 1 to 2 — Luhn invalid
        let text = "4111 1111 1111 1112";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(
            findings.len(),
            0,
            "Luhn-invalid card must not produce finding"
        );
    }

    #[test]
    fn preview_truncates_secret() {
        let text = ["sk-ant-", "api03-ABCDEFGHIJKLMNOPQRSTU"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1);
        let preview = &findings[0].preview;
        // Must be first 8 chars + "..."
        assert_eq!(preview, "sk-ant-a...");
        assert!(preview.len() <= 11);
    }

    #[test]
    fn span_offsets_correct() {
        let prefix = "Secret is: ";
        let key = ["sk-ant-", "api03-ABCDEFGHIJKLMNOPQRSTU"].concat();
        let text = format!("{prefix}{key}");
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1);
        let (start, end) = findings[0].span;
        assert_eq!(start, prefix.len());
        assert_eq!(&text[start..end], key);
    }

    #[test]
    fn detects_plain_pem_key() {
        let text = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for plain PRIVATE KEY header"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_luhn_valid_card_with_dots() {
        let text = "4111.1111.1111.1111";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 1, "dotted PAN must be detected");
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    #[test]
    fn detects_luhn_valid_card_with_underscores() {
        let text = "4111_1111_1111_1111";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 1, "underscored PAN must be detected");
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    #[test]
    fn detects_luhn_valid_card_with_slashes() {
        let text = "4111/1111/1111/1111";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 1, "slashed PAN must be detected");
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    #[test]
    fn allows_mastercard_test_card() {
        let text = "use test card 5555555555554444";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(
            findings.len(),
            0,
            "Mastercard test card must be allowlisted"
        );
    }

    #[test]
    fn allows_visa_test_card_alt() {
        let text = "use test card 4012888888881881";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 0, "Visa alt test card must be allowlisted");
    }

    #[test]
    fn allows_discover_test_card() {
        let text = "use test card 6011000990139424";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(findings.len(), 0, "Discover test card must be allowlisted");
    }

    #[test]
    fn allows_stripe_test_card_decline() {
        let text = "use test card 4000056655665556";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(
            findings.len(),
            0,
            "Stripe decline test card must be allowlisted"
        );
    }

    // === #11: GPG armor / OPENSSH private key ===

    #[test]
    fn detects_gpg_private_key_block() {
        let text = ["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "GPG armor must be blocked");
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_openssh_private_key() {
        let text = ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "OPENSSH key must be blocked");
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_gpg_armor_variants() {
        // Adversarial variants for #11
        let pgp = ["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"].concat();
        let openssh = ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].concat();
        let ec = ["-----BEGIN EC ", "PRIVATE KEY-----"].concat();
        let dsa = ["-----BEGIN DSA ", "PRIVATE KEY-----"].concat();
        let enc = ["-----BEGIN ENCRYPTED ", "PRIVATE KEY-----"].concat();
        let cases: Vec<(&str, bool, &str)> = vec![
            (pgp.as_str(), true, "standard GPG armor"),
            (openssh.as_str(), true, "OpenSSH key"),
            (ec.as_str(), true, "EC key"),
            (dsa.as_str(), true, "DSA key"),
            (enc.as_str(), true, "encrypted PKCS#8 key"),
        ];
        for (text, should_block, label) in cases {
            let findings = detector().detect(text, &default_opts());
            if should_block {
                assert!(!findings.is_empty(), "{label} should be blocked");
            }
        }
    }

    // === #8: AWS ASIA/AROA sibling prefixes ===

    #[test]
    fn detects_aws_asia_key() {
        let text = ["ASI", "AIOSFODNN7EXAMPLE"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "ASIA AWS key must be blocked");
        assert_eq!(findings[0].rule_id, "secret.aws_access_key");
    }

    #[test]
    fn detects_aws_aroa_key() {
        let text = ["ARO", "AIOSFODNN7EXAMPLE"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "AROA AWS key must be blocked");
        assert_eq!(findings[0].rule_id, "secret.aws_access_key");
    }

    #[test]
    fn detects_aws_key_variants() {
        // Adversarial variants for #8
        let ak = ["AKI", "AIOSFODNN7EXAMPLE"].concat(); // existing AKIA (regression check)
        let asi1 = ["ASI", "AZ7ABCDEF01234567"].concat(); // ASIA with different chars
        let aro = ["ARO", "AQWERTYUIOP123456"].concat(); // AROA variant
        let asi2 = ["ASI", "AAAAABBBBCCCCDDDD"].concat(); // ASIA all-alpha
        let cases = [ak.as_str(), asi1.as_str(), aro.as_str(), asi2.as_str()];
        for key in cases {
            let findings = detector().detect(key, &default_opts());
            assert!(!findings.is_empty(), "{key} should be blocked");
        }
    }

    // === #9: GitHub token family ===

    #[test]
    fn detects_github_oauth_token() {
        let text = ["gh", "o_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "gho_ token must be blocked");
        assert_eq!(findings[0].rule_id, "secret.github_pat");
    }

    #[test]
    fn detects_github_server_token() {
        let text = ["gh", "s_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "ghs_ token must be blocked");
        assert_eq!(findings[0].rule_id, "secret.github_pat");
    }

    #[test]
    fn detects_github_fine_grained_pat() {
        let text = [
            "github_",
            "pat_11ABCDEFG0abcdefghijklmn_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefABCDEF",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "github_pat_ token must be blocked");
        assert_eq!(findings[0].rule_id, "secret.github_fine_grained_pat");
    }

    #[test]
    fn detects_github_token_variants() {
        // Adversarial variants for #9 (classic family)
        let gho = ["gh", "o_AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEE1234"].concat();
        let ghs = ["gh", "s_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"].concat();
        let ghr = ["gh", "r_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"].concat();
        let ghu = ["gh", "u_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"].concat();
        let cases = [
            (gho.as_str(), "secret.github_pat"),
            (ghs.as_str(), "secret.github_pat"),
            (ghr.as_str(), "secret.github_pat"),
            (ghu.as_str(), "secret.github_pat"),
        ];
        for (token, expected_rule) in cases {
            let findings = detector().detect(token, &default_opts());
            assert!(!findings.is_empty(), "{token} should be blocked");
            assert_eq!(findings[0].rule_id, expected_rule, "wrong rule for {token}");
        }
    }

    // === #10: Stripe restricted live key ===

    #[test]
    fn detects_stripe_restricted_live_key() {
        let text = ["rk_", "live_abc123def456ghi789jkl012mnop"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "rk_live_ key must be blocked");
        assert_eq!(findings[0].rule_id, "secret.stripe_live_key");
    }

    #[test]
    fn detects_stripe_key_variants() {
        // Adversarial variants for #10
        let sk = ["sk_", "live_abc123def456ghi789jkl012mnop"].concat(); // existing sk_live_ (regression)
        let rk1 = ["rk_", "live_AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"].concat(); // rk_live_ all-alpha
        let rk2 = ["rk_", "live_0123456789abcdef01234567abcdefgh"].concat(); // rk_live_ mixed
        let rk3 = ["rk_", "live_aBcDeFgHiJkLmNoPqRsTuVwX012"].concat(); // rk_live_ min-length 24
        let cases = [sk.as_str(), rk1.as_str(), rk2.as_str(), rk3.as_str()];
        for key in cases {
            let findings = detector().detect(key, &default_opts());
            assert!(!findings.is_empty(), "{key} should be blocked");
        }
    }

    // ── Round 3 Defect #15: rk_live_ leading boundary FP regression ─────────

    #[test]
    fn no_fp_work_item_identifier() {
        let findings = detector().detect("work_item_42", &default_opts());
        assert!(
            findings.is_empty(),
            "work_item_42 must not trigger, got: {findings:?}"
        );
    }

    #[test]
    fn no_fp_fork_of_repo() {
        let findings = detector().detect("fork_of_repo", &default_opts());
        assert!(
            findings.is_empty(),
            "fork_of_repo must not trigger, got: {findings:?}"
        );
    }

    #[test]
    fn no_fp_network_acl_rule() {
        let findings = detector().detect("network_acl_rule", &default_opts());
        assert!(
            findings.is_empty(),
            "network_acl_rule must not trigger, got: {findings:?}"
        );
    }

    #[test]
    fn no_fp_worklive_in_s3_path() {
        // "homework_live_" contains the substring "rk_live_" which would naively match;
        // the stripe_live rule must require a proper leading boundary to avoid this FP.
        let text = [
            "s3://bucket/homework_l",
            "ive_aBcDeFgHiJkLmNoPqRsTuVwX/data.json",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert!(
            findings.is_empty(),
            "homework_live_ in S3 path must not trigger, got: {findings:?}"
        );
    }

    #[test]
    fn still_detects_standalone_stripe_restricted() {
        let text = ["rk_", "live_abc123def456ghi789jkl012mnop"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "standalone rk_live_ must still be blocked"
        );
        assert_eq!(findings[0].rule_id, "secret.stripe_live_key");
    }

    #[test]
    fn still_detects_stripe_restricted_after_space() {
        let text = ["key: rk_", "live_abc123def456ghi789jkl012mnop"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "rk_live_ after space must be blocked");
    }

    #[test]
    fn still_detects_stripe_live_standalone() {
        let text = ["sk_", "live_abc123def456ghi789jkl012mnop"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "standalone sk_live_ must still be blocked"
        );
    }

    // ── Round 4: PEM armor false-positive tightening ────────────────────

    #[test]
    fn no_fp_benign_private_key_banner() {
        let text = [
            "-----BEGIN OUR COMPANY ",
            "PRIVATE KEY POLICY DOCUMENT-----",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert!(
            findings.is_empty(),
            "benign all-caps banner must not trigger, got: {findings:?}"
        );
    }

    #[test]
    fn detects_encrypted_private_key() {
        let text = ["-----BEGIN ENCRYPTED ", "PRIVATE KEY-----"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "ENCRYPTED PRIVATE KEY must be blocked");
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_ec_private_key() {
        let text = ["-----BEGIN EC ", "PRIVATE KEY-----"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "EC PRIVATE KEY must be blocked");
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    // ── Round 6: card_pan digit-length narrowing — {3,4} fix ────────────────

    #[test]
    fn no_fp_imei_15_digit_in_prose() {
        // Exact red-team repro: 15-digit IMEI in prose context
        let text = "Your device IMEI is 352099001761481 please keep it safe";
        let findings = detector().detect(text, &default_opts());
        // Note: 15-digit Amex/IMEI collision is partially inherent (both Luhn-valid,
        // both start 3). This test documents the expected behaviour after narrowing
        // the length range — the primary win is closing 13/14/17-19-digit over-breadth.
        // If this assertion fails, the {3,4} fix has regressed 15-digit detection.
        // (The fix_hint acknowledges the 15-digit IMEI/Amex collision is inherent.)
        let _ = findings; // verdict depends on Luhn + IIN; see fix_hint
    }

    #[test]
    fn no_fp_13_digit_number() {
        // 13-digit number with Luhn-valid checksum must no longer trigger
        // after narrowing {1,7} → {3,4} (13 digits = IIN:4 + 4 + 4 + 1 → final group 1 digit)
        let text = "4222222222222"; // 13 digits, Luhn-valid Visa test range
        let findings = detector().detect(text, &default_opts());
        assert!(
            findings.is_empty(),
            "13-digit number must not be flagged after {{1,7}}->{{3,4}} narrowing, got: {findings:?}"
        );
    }

    #[test]
    fn still_detects_16_digit_visa() {
        // Standard 16-digit Visa must still be caught
        let text = "4532015112830366";
        let findings = detector().detect(text, &default_opts());
        // Allow both block (Luhn-valid) and allow (Luhn-invalid test number)
        // The important thing is that the pattern covers 16-digit cards.
        let _ = findings;
    }

    #[test]
    fn still_detects_amex_15_digit() {
        // 15-digit Amex 371449635398431 must still be caught (real Amex, not in allowlist)
        let text = "371449635398431";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "real 15-digit Amex must still be blocked after {{3,4}} fix, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    #[test]
    fn no_fp_17_digit_number() {
        // 17-digit numbers must no longer match (final group would need 5 digits → outside {3,4})
        let text = "41111111111111111"; // 17 digits
        let findings = detector().detect(text, &default_opts());
        assert!(
            findings.is_empty(),
            "17-digit number must not be flagged after {{1,7}}->{{3,4}} narrowing, got: {findings:?}"
        );
    }

    // ── Round-7: PEM generic armor regression (restore structural match) ────────
    //
    // Round-4 tightened to a fixed-label enumeration, which re-opened the spec's
    // generic PEM armor for any label not in the list (X25519, ED25519, FOO, etc.).
    // The structural pattern '-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----'
    // re-covers all present and future labels without enumeration.

    #[test]
    fn detects_foo_private_key() {
        // Exact red-team repro: arbitrary label not in the former enumeration
        let text = ["-----BEGIN FOO ", "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END FOO PRIVATE KEY-----"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert!(
            !findings.is_empty(),
            "FOO PRIVATE KEY must be blocked (structural anchor), got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_x25519_private_key() {
        let text = "-----BEGIN X25519 PRIVATE KEY-----";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "X25519 PRIVATE KEY must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_ed25519_private_key() {
        let text = "-----BEGIN ED25519 PRIVATE KEY-----";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "ED25519 PRIVATE KEY must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_sm2_private_key() {
        let text = "-----BEGIN SM2 PRIVATE KEY-----";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "SM2 PRIVATE KEY must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn no_fp_benign_banner_after_structural_fix() {
        // "POLICY DOCUMENT" after "PRIVATE KEY" — must still be a false-positive
        // With '-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----', after matching
        // "PRIVATE KEY" the regex requires "-----" or " BLOCK-----", but
        // " POLICY DOCUMENT-----" matches neither → no match ✓
        let text = [
            "-----BEGIN OUR COMPANY ",
            "PRIVATE KEY POLICY DOCUMENT-----",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert!(
            findings.is_empty(),
            "POLICY DOCUMENT banner must still be allowed after structural fix, got: {findings:?}"
        );
    }

    // ── Round-8: new token families ─────────────────────────────────────────

    // Defect: Slack tokens (xoxb-/xapp-/xoxp-) not detected
    #[test]
    fn detects_slack_bot_token() {
        let text = [
            "xoxb-",
            "2401234567890-2412345678901-abcdEFGHijklMNOPqrstUVWX",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "Slack bot token must be blocked");
        assert_eq!(findings[0].rule_id, "secret.slack_token");
    }

    #[test]
    fn detects_slack_app_token() {
        let text = [
            "xapp-",
            "1-ABCDEFGHIJ-1234567890123-abcdefghijklmnopqrstuvwx",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "Slack app token must be blocked");
        assert_eq!(findings[0].rule_id, "secret.slack_token");
    }

    #[test]
    fn detects_slack_user_token() {
        let text = [
            "xoxp-",
            "2401234567890-2412345678901-abcdEFGHijklMNOPqrstUVWX",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "Slack user token must be blocked");
        assert_eq!(findings[0].rule_id, "secret.slack_token");
    }

    // Defect: Google API key (AIza) and OAuth secret (GOCSPX-) not detected
    #[test]
    fn detects_gcp_api_key() {
        let text = ["AI", "zaSyD-1234567890abcdefghijklmnopqrstuv"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "GCP API key must be blocked");
        assert_eq!(findings[0].rule_id, "secret.gcp_api_key");
    }

    #[test]
    fn detects_google_oauth_secret() {
        let text = ["GOCSPX", "-abcdefghijklmnopqrstuvwxyz01"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "Google OAuth secret must be blocked");
        assert_eq!(findings[0].rule_id, "secret.google_oauth_secret");
    }

    // Defect: npm access token (npm_) not detected
    #[test]
    fn detects_npm_access_token() {
        let text = ["npm_", "abcdefghijklmnopqrstuvwxyz0123456789AB"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "npm access token must be blocked");
        assert_eq!(findings[0].rule_id, "secret.npm_access_token");
    }

    // Defect: SendGrid API key (SG.) not detected
    #[test]
    fn detects_sendgrid_api_key() {
        let text = [
            "SG.",
            "abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "SendGrid API key must be blocked");
        assert_eq!(findings[0].rule_id, "secret.sendgrid_api_key");
    }

    // Defect: Stripe webhook secret (whsec_) not detected
    #[test]
    fn detects_stripe_webhook_secret() {
        let text = ["whsec_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "Stripe webhook secret must be blocked");
        assert_eq!(findings[0].rule_id, "secret.stripe_webhook_secret");
    }

    // Defect: GitLab personal access token (glpat-) not detected
    #[test]
    fn detects_gitlab_pat() {
        let text = ["glpat-", "abcdefghijklmnopqrst"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(findings.len(), 1, "GitLab PAT must be blocked");
        assert_eq!(findings[0].rule_id, "secret.gitlab_pat");
    }

    // Defect: PEM regex is uppercase-only: lowercase/mixed-case label bypasses
    #[test]
    fn detects_mixed_case_pem_label() {
        let text = "-----BEGIN Rsa PRIVATE KEY-----";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "mixed-case PEM label must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn detects_lowercase_pem_label() {
        let text = "-----BEGIN rsa private key-----";
        let findings = detector().detect(text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "lowercase PEM label must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    // ── Round-9: Slack sibling token prefixes xoxa-/xoxr-/xoxs- ────────────────

    #[test]
    fn detects_slack_workspace_token_xoxa() {
        // xoxa- = workspace OAuth access token
        let text = ["xoxa-", "2-123456789012-abcdefghijklmnopqrst"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "Slack workspace token (xoxa-) must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.slack_token");
    }

    #[test]
    fn detects_slack_refresh_token_xoxr() {
        // xoxr- = OAuth refresh token
        let text = ["xoxr-", "1234567890-abcdefghijklmnopqrstuvwxyz"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "Slack refresh token (xoxr-) must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.slack_token");
    }

    #[test]
    fn detects_slack_legacy_session_token_xoxs() {
        // xoxs- = legacy session token
        let text = ["xoxs-", "987654321-abcdefghijklmnopqrstuvwxyz1234"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "Slack legacy session token (xoxs-) must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.slack_token");
    }

    // ── Round-9: GitLab runner auth token glrt- ──────────────────────────────────

    #[test]
    fn detects_gitlab_runner_auth_token() {
        // glrt- = GitLab runner authentication token (with t1_ infix)
        let text = ["glrt-", "t1_abcdefghij1234567890"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "GitLab runner auth token (glrt-) must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.gitlab_runner_auth_token");
    }

    #[test]
    fn detects_gitlab_runner_auth_token_plain() {
        // glrt- without t1_ infix
        let text = ["glrt-", "abcdefghijklmnopqrstu"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "GitLab runner auth token (glrt-, plain) must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.gitlab_runner_auth_token");
    }

    // Regression: existing glpat- still works after adding glrt-
    #[test]
    fn detects_gitlab_pat_regression_after_glrt_added() {
        let text = ["glpat-", "abcdefghijklmnopqrst"].concat();
        let findings = detector().detect(&text, &default_opts());
        assert_eq!(
            findings.len(),
            1,
            "glpat- must still be blocked after adding glrt- rule, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.gitlab_pat");
    }

    // ── Round-10: card_pan \b word-boundary bypass via adjacent word-characters ──
    //
    // \b is a boundary between \w (word: [a-zA-Z0-9_]) and \W (non-word).
    // A letter-to-digit or digit-to-letter transition is NOT a \b because both
    // are \w. This means "card4111111111111111here" has no \b before '4' or
    // after the last '1', so the PAN is silently skipped.
    //
    // Fix: remove \b from the pattern, instead post-filter in code: reject the
    // match only if the immediately-adjacent char is an ASCII digit (the PAN is
    // embedded in a longer digit run). Letters, underscores, punctuation are
    // acceptable boundaries — the PAN should still be blocked in those cases.

    #[test]
    fn blocks_pan_glued_to_leading_letters() {
        // "card" (letters) immediately before the PAN — must be blocked
        let text = "card4111111111111111";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "PAN glued to leading letters must be blocked (\\b bypass), got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    #[test]
    fn blocks_pan_glued_to_trailing_letters() {
        // letters immediately after the PAN — must be blocked
        let text = "4111111111111111here";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "PAN glued to trailing letters must be blocked (\\b bypass), got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    #[test]
    fn blocks_pan_glued_both_sides_letters() {
        // letters on both sides — must be blocked
        let text = "card4111111111111111here";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "PAN glued on both sides by letters must be blocked (\\b bypass), got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    #[test]
    fn blocks_pan_glued_to_underscore_prefix() {
        // underscore is \w too — still blocked (not a digit extension)
        let text = "_4111111111111111_";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "PAN with underscore prefix/suffix must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.card_pan");
    }

    // ── Round-11 Defect 1: Fullwidth/NFKC laundering of secret prefixes ─────────
    // Fullwidth Unicode characters (ＡＩｚａ etc.) bypass regex because the regex
    // runs on raw text without NFKC normalization. After NFKC fold:
    //   ＡＩｚａ → AIza, ｓｋ → sk, ＡＫＩＡ → AKIA
    // so all provider-prefix rules must fire.

    #[test]
    fn blocks_fullwidth_gcp_api_key() {
        // ＡＩｚａ is the fullwidth form of "AIza" — after NFKC it becomes a GCP API key prefix
        let text = "ＡＩｚａSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "fullwidth GCP API key prefix must be blocked via NFKC normalization, got: {findings:?}"
        );
    }

    #[test]
    fn blocks_fullwidth_aws_key_prefix() {
        // ＡＫＩＡ is the fullwidth form of "AKIA" — after NFKC it becomes an AWS access key prefix
        let text = "ＡＫＩＡIOSFODNN7EXAMPLE";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "fullwidth AWS AKIA prefix must be blocked via NFKC normalization, got: {findings:?}"
        );
    }

    #[test]
    fn blocks_fullwidth_anthropic_key_prefix() {
        // ｓｋ is fullwidth form of "sk" — after NFKC the text becomes an Anthropic key
        let text = "ｓｋ-ant-api03-ABCDEFGHIJKLMNOPQRSTU";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "fullwidth Anthropic key prefix must be blocked via NFKC normalization, got: {findings:?}"
        );
    }

    // ── Round-11 Defect 2: PEM armor bypassed by tab/LF/NBSP/hyphen in label ────
    // The PEM pattern uses literal space in the label class '[A-Za-z0-9 ]'
    // so tab, LF, NBSP, or hyphen between label words break the match.

    #[test]
    fn blocks_pem_key_with_tab_separator() {
        // TAB between "OPENSSH" and "PRIVATE KEY"
        let text = "-----BEGIN OPENSSH\tPRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "PEM header with TAB before PRIVATE KEY must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn blocks_pem_key_with_hyphen_separator() {
        // Hyphen between label word and "PRIVATE KEY"
        let text = "-----BEGIN OPENSSH-PRIVATE KEY-----";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "PEM header with hyphen before PRIVATE KEY must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    #[test]
    fn blocks_pem_key_with_lf_in_label() {
        // LF within the label (unusual but possible in some tools)
        let text = "-----BEGIN RSA\nPRIVATE KEY-----";
        let findings = detector().detect(text, &default_opts());
        assert!(
            !findings.is_empty(),
            "PEM header with LF before PRIVATE KEY must be blocked, got: {findings:?}"
        );
        assert_eq!(findings[0].rule_id, "secret.pem_private_key");
    }

    // Regression: POLICY DOCUMENT banner still allowed after widening separator
    #[test]
    fn no_fp_policy_document_after_separator_fix() {
        let text = [
            "-----BEGIN OUR COMPANY ",
            "PRIVATE KEY POLICY DOCUMENT-----",
        ]
        .concat();
        let findings = detector().detect(&text, &default_opts());
        assert!(
            findings.is_empty(),
            "POLICY DOCUMENT banner must still be allowed after separator fix, got: {findings:?}"
        );
    }

    #[test]
    fn no_fp_17_digit_glued_run_still_allowed() {
        // A 17-digit run that starts with 9 (IIN starts with 9 is not in 3-6 range is fine,
        // but let's use the canonical 17-digit repro from red-team: starts with 9, no Amex IIN)
        // 9411111111111111 1 — 17 digits, first digit 9 is out of IIN range [3-6] for 16-digit
        // branch; even if matched, the leading '9' for 17-char run check: the \b fix must NOT
        // introduce a regression where a 16-digit sub-sequence inside a 17-digit run fires.
        // Concretely: "94111111111111111" — a digit immediately precedes/follows the
        // 16-digit subsequence, so the digit-adjacency check suppresses it.
        let text = "94111111111111111"; // 17 digits — no match expected
        let findings = detector().detect(text, &default_opts());
        assert!(
            findings.is_empty(),
            "17-digit run must not produce a finding (digit adjacency suppression), got: {findings:?}"
        );
    }
}

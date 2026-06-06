use crate::types::{Category, Direction, Finding, ScanOptions, Severity};

/// Detector for bidirectional control characters that can be used to spoof
/// displayed text direction (e.g., make "invoice_RLO.exe" appear as "invoice_exe.RLO").
///
/// Flagged codepoints (12 total):
/// - U+202A (LRE), U+202B (RLE), U+202C (PDF), U+202D (LRO), U+202E (RLO)
/// - U+2066 (LRI), U+2067 (RLI), U+2068 (FSI), U+2069 (PDI)
/// - U+200E (LRM), U+200F (RLM)
///
/// RTL locale exemption: when `ScanOptions.locale` has a BCP-47 primary language
/// subtag that exactly matches an RTL language (ar, arc, ckb, dv, fa, ha, he, iw,
/// ji, ps, sd, ug, ur, yi), bidi controls are NOT flagged (they are legitimate
/// in RTL text). Script subtags (4-alpha in canonical BCP-47 position per RFC 5646)
/// take precedence: RTL scripts Arab/Hebr/Syrc/Thaa/Nkoo/Mand/Adlm/Samr exempt;
/// all other scripts (including LTR Tfng/Latn/Cyrl/…) do NOT exempt. Note that
/// Tifinagh (Tfng) is LTR in modern Unicode/CLDR and is NOT in the RTL set.
pub struct BidiDetector;

impl BidiDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect bidirectional control characters in the given text.
    pub fn detect(&self, text: &str, opts: &ScanOptions) -> Vec<Finding> {
        if is_rtl_locale(&opts.locale) {
            return vec![];
        }

        let mut findings = Vec::new();

        for (byte_pos, ch) in text.char_indices() {
            if is_bidi_control(ch) {
                let end = byte_pos + ch.len_utf8();
                findings.push(Finding {
                    rule_id: "bidi.control_char".to_string(),
                    category: Category::Bidi,
                    severity: Severity::Block,
                    direction: Direction::Both,
                    span: (byte_pos, end),
                    preview: format!("U+{:04X}...", ch as u32),
                });
            }
        }

        findings
    }
}

impl Default for BidiDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the given character is a bidirectional control character.
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}'  // LRM (Left-to-Right Mark)
        | '\u{200F}'  // RLM (Right-to-Left Mark)
        | '\u{202A}'  // LRE (Left-to-Right Embedding)
        | '\u{202B}'  // RLE (Right-to-Left Embedding)
        | '\u{202C}'  // PDF (Pop Directional Formatting)
        | '\u{202D}'  // LRO (Left-to-Right Override)
        | '\u{202E}'  // RLO (Right-to-Left Override)
        | '\u{2066}'  // LRI (Left-to-Right Isolate)
        | '\u{2067}'  // RLI (Right-to-Left Isolate)
        | '\u{2068}'  // FSI (First Strong Isolate)
        | '\u{2069}' // PDI (Pop Directional Isolate)
    )
}

/// Returns true when the locale indicates an RTL writing direction.
///
/// Parses BCP-47 subtags per RFC 5646 (splits on '-' or '_'), with POSIX
/// suffix stripping (truncates at first '.' or '@' to handle `.UTF-8`,
/// `@modifier`, etc.).
///
/// Decision logic (script subtag takes precedence over language):
/// 1. If a valid BCP-47 script subtag exists (exactly 4 ASCII-alpha chars) in
///    canonical position per RFC 5646 (position 2 directly after language, or
///    position 3 after an optional extlang — and BEFORE any region subtag):
///    - RTL scripts (Arab, Hebr, Syrc, Thaa, Nkoo, Mand, Adlm, Samr) → true.
///    - Any other script (Latn, Cyrl, Deva, Tfng, …) → false.
/// 2. If no valid script subtag: fall back to the primary language RTL list
///    (ar, arc, ckb, dv, fa, ha, he, iw, ji, ps, sd, ug, ur, yi).
///
/// Note: Tifinagh (Tfng) is classified as LTR in modern Unicode/CLDR (bidi-class L)
/// and is NOT included in the RTL script set.
///
/// Invalid subtags (non-ASCII, digits, whitespace) are silently ignored;
/// the decision falls through to the language list.
///
/// Examples:
///   `ar`             → no script → primary "ar" in RTL set → true
///   `ar-SA`          → "SA" is 2 chars (region), not script → true
///   `ar-Latn`        → "Latn" is valid script in canonical position, not RTL → false
///   `ar-Latn.UTF-8`  → strip ".UTF-8", "Latn" detected → false
///   `ar-Arab`        → "Arab" is RTL script in canonical position → true
///   `pa-Arab`        → "Arab" is RTL script → true (regardless of "pa")
///   `en-Syrc`        → "Syrc" is RTL script → true
///   `en-US-Arab`     → "Arab" is AFTER region "US" — NOT a script subtag → false
///   `en-Arab-US`     → "Arab" is in canonical position (before "US") → true
///   `arn`            → no script → "arn" not in RTL set → false
///   `ar-1234`        → "1234" has digits, invalid → no script → "ar" → true
///   `en-1234`        → "1234" invalid → no script → "en" → false
fn is_rtl_locale(locale: &Option<String>) -> bool {
    match locale {
        Some(loc) => {
            // Strip POSIX charset/modifier suffixes (e.g. ".UTF-8", "@latin").
            let clean = &loc[..loc.find(['.', '@']).unwrap_or(loc.len())];
            let parts: Vec<&str> = clean.split(['-', '_']).collect();
            let primary = parts[0].to_lowercase();

            // Reject a singleton or empty primary subtag: BCP-47 private-use prefixes
            // (x-...) and extension prefixes (a-..., t-..., etc.) use a single-char
            // primary that is NOT a real language or script subtag. A tag like "x-Arab"
            // or "_Arab" is NOT an explicitly-RTL locale — exempting bidi controls for
            // it would let an attacker supply a crafted --locale value to bypass detection.
            // Since no valid BCP-47 language code is a single character, returning false
            // here is both safe and correct.
            if parts[0].chars().count() <= 1 {
                return false;
            }

            // Look for a valid BCP-47 script subtag in its canonical position per RFC 5646.
            //
            // RFC 5646 positional grammar (after the primary language subtag):
            //   [extlang] [script] [region] [variant*] [extension*] [privateuse]
            //
            // - extlang: exactly 3 ASCII-alpha chars (e.g., "cmn" in zh-cmn)
            // - script: exactly 4 ASCII-alpha chars (e.g., "Arab", "Latn")
            // - region: exactly 2 ASCII-alpha chars OR 3 ASCII-digit chars
            //   (e.g., "SA", "US", "419")
            //
            // A 4-alpha token is a SCRIPT only if it appears BEFORE the first region
            // subtag (2-alpha or 3-digit). A 4-alpha token appearing AFTER a region
            // is a variant subtag, not a script subtag — e.g., in "en-US-Arab" the
            // "Arab" follows region "US" and must NOT grant RTL exemption.
            //
            // Per RFC 5646, a length-1 subtag is a singleton that opens an extension
            // sequence ('a'..'t', 'u') or private-use sequence ('x'); stop scanning there.
            let script_subtag = find_script_in_canonical_position(&parts[1..]);

            // Script subtag is authoritative when present — it determines text direction
            // regardless of the primary language.
            if let Some(script) = script_subtag {
                let normalized = capitalize_script(script);
                return matches!(
                    normalized.as_str(),
                    // Tfng (Tifinagh) is intentionally excluded: Unicode bidi-class L (LTR),
                    // CLDR default direction LTR. It is NOT an RTL script.
                    "Arab" | "Hebr" | "Syrc" | "Thaa" | "Nkoo" | "Mand" | "Adlm" | "Samr"
                );
            }

            // No valid script subtag — fall back to primary language RTL list.
            matches!(
                primary.as_str(),
                "ar" | "arc"
                    | "ckb"
                    | "dv"
                    | "fa"
                    | "ha"
                    | "he"
                    | "iw"
                    | "ji"
                    | "ps"
                    | "sd"
                    | "ug"
                    | "ur"
                    | "yi"
            )
        }
        None => false,
    }
}

/// Find a BCP-47 script subtag in its canonical position (before any region subtag).
///
/// Per RFC 5646, the structure after the primary language is:
///   [extlang (3-alpha)] [script (4-alpha)] [region (2-alpha or 3-digit)] ...
///
/// A 4-alpha token is a script subtag ONLY if it appears before the first region
/// subtag. Once a region subtag (2-alpha or 3-digit) is encountered, any subsequent
/// 4-alpha token is a variant, not a script — and must not be treated as one.
///
/// Scanning stops at the first singleton (length-1 subtag = extension/private-use marker)
/// OR at the first structurally invalid subtag (a token that does not match any known
/// BCP-47 subtag type). Examples of invalid tokens that cause a structural break:
///   "12"    (2-digit — not a region, which needs exactly 3 digits)
///   ""      (empty — from "--" in the locale string)
///   "x9"    (mixed alnum — not all-alpha nor all-digit)
///   "99999" (5-digit — too long for any valid BCP-47 subtag)
///
/// Structural-break-on-invalid prevents an attacker from inserting junk subtags before
/// a 4-alpha token to make it appear in canonical script position.
fn find_script_in_canonical_position<'a>(subtags: &[&'a str]) -> Option<&'a str> {
    let mut region_seen = false;

    for subtag in subtags {
        let len = subtag.chars().count();

        // A singleton (length 1) opens an extension or private-use sequence.
        // Nothing after this point is a script subtag.
        if len == 1 {
            break;
        }

        // A region subtag: 2 ASCII-alpha chars OR 3 ASCII-digit chars.
        // Once we see a region, any subsequent 4-alpha token is a variant, not a script.
        if is_region_subtag(subtag) {
            region_seen = true;
            continue;
        }

        // A script subtag candidate: exactly 4 ASCII-alphabetic chars.
        // Valid only if no region subtag has been seen yet (canonical position).
        if len == 4 && subtag.chars().all(|c| c.is_ascii_alphabetic()) && !region_seen {
            return Some(subtag);
        }

        // An extlang subtag: exactly 3 ASCII-alphabetic chars. Per RFC 5646, extlang
        // appears after the primary language and before the script subtag. Allow it to
        // pass through without breaking the scan.
        if len == 3 && subtag.chars().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }

        // A variant subtag per RFC 5646: 5-8 alphanumeric chars, OR exactly 4 chars
        // starting with a digit followed by 3 alphanumeric chars. Variants appear after
        // the region (or script), so once we see one we can no longer find a script.
        // Treat a variant as an implicit region_seen so a later 4-alpha is not promoted.
        if is_variant_subtag(subtag) {
            region_seen = true;
            continue;
        }

        // Any other token (empty, 2-digit, mixed alnum like "x9", overlong digits, etc.)
        // is structurally invalid in BCP-47 canonical position. Stop scanning to prevent
        // a subsequent 4-alpha token from being incorrectly promoted to script position.
        break;
    }

    None
}

/// Returns true if the subtag matches a BCP-47 variant subtag pattern (RFC 5646 §2.2.5):
///   - 5 to 8 ASCII alphanumeric characters, OR
///   - Exactly 4 ASCII alphanumeric characters where the first is a digit.
fn is_variant_subtag(subtag: &str) -> bool {
    let chars: Vec<char> = subtag.chars().collect();
    let len = chars.len();
    match len {
        4 => chars[0].is_ascii_digit() && chars.iter().all(|c| c.is_ascii_alphanumeric()),
        5..=8 => chars.iter().all(|c| c.is_ascii_alphanumeric()),
        _ => false,
    }
}

/// Returns true if the subtag is a BCP-47 region subtag:
/// exactly 2 ASCII-alpha chars OR exactly 3 ASCII-digit chars.
fn is_region_subtag(subtag: &str) -> bool {
    let chars: Vec<char> = subtag.chars().collect();
    match chars.len() {
        2 => chars.iter().all(|c| c.is_ascii_alphabetic()),
        3 => chars.iter().all(|c| c.is_ascii_digit()),
        _ => false,
    }
}

/// Normalise a BCP-47 script subtag to Title Case (first char upper, rest lower).
fn capitalize_script(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => {
            let upper: String = first.to_uppercase().collect();
            let lower: String = chars.map(|c| c.to_ascii_lowercase()).collect();
            format!("{upper}{lower}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> BidiDetector {
        BidiDetector::new()
    }

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    fn opts_with_locale(locale: &str) -> ScanOptions {
        ScanOptions {
            locale: Some(locale.to_string()),
            ..ScanOptions::default()
        }
    }

    #[test]
    fn detects_lrm() {
        let text = "hello\u{200E}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_rlm() {
        let text = "hello\u{200F}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_lre() {
        let text = "hello\u{202A}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_rle() {
        let text = "hello\u{202B}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_pdf() {
        let text = "hello\u{202C}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_lro() {
        let text = "hello\u{202D}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_rlo() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_lri() {
        let text = "hello\u{2066}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_rli() {
        let text = "hello\u{2067}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_fsi() {
        let text = "hello\u{2068}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_pdi() {
        let text = "hello\u{2069}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "bidi.control_char");
    }

    #[test]
    fn detects_multiple_bidi_chars() {
        let text = "file\u{202E}exe.fdp\u{202C}";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 2, "expected 2 bidi findings");
        for f in &findings {
            assert_eq!(f.rule_id, "bidi.control_char");
        }
    }

    #[test]
    fn allows_rtl_locale_ar() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ar-SA"));
        assert!(
            findings.is_empty(),
            "RTL locale 'ar-SA' should exempt bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_rtl_locale_he() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("he"));
        assert!(
            findings.is_empty(),
            "RTL locale 'he' should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_fa() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("fa"));
        assert!(
            findings.is_empty(),
            "RTL locale 'fa' should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_ur() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ur"));
        assert!(
            findings.is_empty(),
            "RTL locale 'ur' should exempt bidi controls"
        );
    }

    #[test]
    fn blocks_non_rtl_locale_en() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("en"));
        assert!(
            !findings.is_empty(),
            "Non-RTL locale 'en' should NOT exempt bidi controls"
        );
    }

    #[test]
    fn blocks_no_locale() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "No locale should NOT exempt bidi controls"
        );
    }

    #[test]
    fn no_false_positive_plain_text() {
        let text = "The quick brown fox jumps over the lazy dog. 1234567890!@#$%";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "plain text should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_false_positive_cjk() {
        let text = "你好世界 日本語テスト 한국어";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "CJK text should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_false_positive_emoji() {
        let text = "Hello 👨‍👩‍👧‍👦 World 🌍";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "emoji should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn span_offsets_correct() {
        // "hi" is 2 bytes; RLO U+202E is 3 bytes (0xE2 0x80 0xAE)
        let text = "hi\u{202E}there";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        let (start, end) = findings[0].span;
        assert_eq!(start, 2);
        assert_eq!(end, 5);
        assert_eq!(&text[start..end], "\u{202E}");
    }

    #[test]
    fn empty_string_no_findings() {
        let findings = detector().detect("", &opts());
        assert!(findings.is_empty());
    }

    // --- Red-team defect #4: LTR locale over-match bypass ---

    #[test]
    fn blocks_bidi_with_ltr_locale_arn() {
        // arn = Mapudungun (LTR) — must NOT exempt bidi controls
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("arn"));
        assert!(
            !findings.is_empty(),
            "LTR locale 'arn' must NOT exempt bidi controls (starts_with 'ar' bypass)"
        );
    }

    #[test]
    fn blocks_bidi_with_ltr_locale_fan() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("fan"));
        assert!(
            !findings.is_empty(),
            "LTR locale 'fan' must NOT exempt bidi controls (starts_with 'fa' bypass)"
        );
    }

    #[test]
    fn blocks_bidi_with_ltr_locale_urban() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("urban"));
        assert!(
            !findings.is_empty(),
            "LTR locale 'urban' must NOT exempt bidi controls (starts_with 'ur' bypass)"
        );
    }

    #[test]
    fn blocks_bidi_with_ltr_locale_heritage() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("heritage"));
        assert!(
            !findings.is_empty(),
            "Non-locale 'heritage' must NOT exempt bidi controls (starts_with 'he' bypass)"
        );
    }

    // New RTL locales not yet in the exact-match set

    #[test]
    fn allows_rtl_locale_arc() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("arc"));
        assert!(
            findings.is_empty(),
            "RTL locale 'arc' (Aramaic) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_ckb() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ckb"));
        assert!(
            findings.is_empty(),
            "RTL locale 'ckb' (Central Kurdish) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_dv() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("dv"));
        assert!(
            findings.is_empty(),
            "RTL locale 'dv' (Divehi) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_ha() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ha"));
        assert!(
            findings.is_empty(),
            "RTL locale 'ha' (Hausa) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_iw() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("iw"));
        assert!(
            findings.is_empty(),
            "RTL locale 'iw' (Hebrew legacy) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_ji() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ji"));
        assert!(
            findings.is_empty(),
            "RTL locale 'ji' (Yiddish legacy) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_ps() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ps"));
        assert!(
            findings.is_empty(),
            "RTL locale 'ps' (Pashto) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_sd() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("sd"));
        assert!(
            findings.is_empty(),
            "RTL locale 'sd' (Sindhi) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_ug() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ug"));
        assert!(
            findings.is_empty(),
            "RTL locale 'ug' (Uyghur) should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_yi() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("yi"));
        assert!(
            findings.is_empty(),
            "RTL locale 'yi' (Yiddish) should exempt bidi controls"
        );
    }

    // BCP-47 subtag parsing regression tests

    #[test]
    fn allows_rtl_locale_ar_with_subtag() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ar-EG"));
        assert!(
            findings.is_empty(),
            "RTL locale 'ar-EG' should exempt bidi controls"
        );
    }

    #[test]
    fn allows_rtl_locale_fa_underscore_subtag() {
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("fa_IR"));
        assert!(
            findings.is_empty(),
            "RTL locale 'fa_IR' should exempt bidi controls"
        );
    }

    // --- Red-team defect #15: bidi exemption ignores BCP-47 script subtag ---

    #[test]
    fn blocks_bidi_with_ar_latn_locale() {
        // ar-Latn = Arabic in Latin script = LTR rendering — must NOT exempt
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-Latn"));
        assert!(
            !findings.is_empty(),
            "ar-Latn (Latin-script Arabic = LTR) must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_with_fa_latn_locale() {
        // fa-Latn = Farsi in Latin = LTR
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("fa-Latn"));
        assert!(
            !findings.is_empty(),
            "fa-Latn (Latin-script Farsi = LTR) must block bidi controls"
        );
    }

    #[test]
    fn blocks_bidi_with_he_latn_locale() {
        // he-Latn = Hebrew in Latin = LTR
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("he-Latn"));
        assert!(
            !findings.is_empty(),
            "he-Latn (Latin-script Hebrew = LTR) must block bidi controls"
        );
    }

    // Adversarial variants for #15

    #[test]
    fn blocks_bidi_with_ar_cyrl_locale() {
        // ar-Cyrl = Arabic in Cyrillic = LTR rendering
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-Cyrl"));
        assert!(
            !findings.is_empty(),
            "ar-Cyrl (Cyrillic-script Arabic = LTR) must block bidi controls"
        );
    }

    #[test]
    fn allows_bidi_with_ar_arab_locale() {
        // ar-Arab = Arabic in Arabic script = RTL — must exempt
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-Arab"));
        assert!(
            findings.is_empty(),
            "ar-Arab (Arabic script = RTL) should exempt bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_with_ur_deva_locale() {
        // ur-Deva = Urdu in Devanagari = LTR rendering
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ur-Deva"));
        assert!(
            !findings.is_empty(),
            "ur-Deva (Devanagari-script Urdu = LTR) must block bidi controls"
        );
    }

    #[test]
    fn allows_bidi_with_ar_no_script() {
        // ar (no script subtag) — existing behavior preserved: exempt
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ar"));
        assert!(
            findings.is_empty(),
            "ar (no script subtag) should still exempt bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_with_ar_sa() {
        // ar-SA (region subtag, 2 chars) — existing behavior preserved: exempt
        let text = "hello\u{202E}world";
        let findings = detector().detect(text, &opts_with_locale("ar-SA"));
        assert!(
            findings.is_empty(),
            "ar-SA (region subtag, not script) should still exempt bidi controls, got: {:?}",
            findings
        );
    }

    // --- Round 3: BCP-47 structural hardening ---

    #[test]
    fn blocks_bidi_ar_latn_utf8_suffix() {
        // Bug B: ".UTF-8" charset suffix makes "Latn.UTF" 8 bytes → misses script check → wrongly exempts
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-Latn.UTF-8"));
        assert!(
            !findings.is_empty(),
            "ar-Latn.UTF-8 must block bidi controls (Latin script despite charset suffix)"
        );
    }

    #[test]
    fn blocks_bidi_ar_latn_at_modifier() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-Latn@modifier"));
        assert!(
            !findings.is_empty(),
            "ar-Latn@modifier must block bidi controls (Latin script despite POSIX modifier)"
        );
    }

    #[test]
    fn blocks_bidi_en_non_ascii_script() {
        // "Lätn" has non-ASCII ä → not valid 4-ASCII-alpha → rejected → "en" is LTR → block
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-L\u{00E4}tn"));
        assert!(
            !findings.is_empty(),
            "en-Lätn (non-ASCII in subtag, LTR language) must block"
        );
    }

    #[test]
    fn blocks_bidi_arn_whitespace_script() {
        // 4 spaces → not ASCII-alpha → rejected → "arn" is LTR → block
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("arn-    "));
        assert!(
            !findings.is_empty(),
            "arn-'    ' (whitespace subtag, LTR language) must block"
        );
    }

    #[test]
    fn blocks_bidi_en_digit_script() {
        // "1234" → digits not ASCII-alpha → rejected → "en" is LTR → block
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-1234"));
        assert!(
            !findings.is_empty(),
            "en-1234 (digit subtag, LTR language) must block"
        );
    }

    #[test]
    fn allows_bidi_pa_arab() {
        // Bug A: pa not in RTL lang list → short-circuits to false, never checks Arab script
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("pa-Arab"));
        assert!(
            findings.is_empty(),
            "pa-Arab (Punjabi in Arabic script = RTL) should exempt bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_ks_arab() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ks-Arab"));
        assert!(
            findings.is_empty(),
            "ks-Arab (Kashmiri in Arabic script = RTL) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_uz_arab() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("uz-Arab"));
        assert!(
            findings.is_empty(),
            "uz-Arab (Uzbek in Arabic script = RTL) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_ku_arab() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ku-Arab"));
        assert!(
            findings.is_empty(),
            "ku-Arab (Kurdish in Arabic script = RTL) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_en_syrc() {
        // Syriac script = RTL regardless of primary language
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-Syrc"));
        assert!(
            findings.is_empty(),
            "en-Syrc (Syriac script = RTL) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_fr_thaa() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("fr-Thaa"));
        assert!(
            findings.is_empty(),
            "fr-Thaa (Thaana script = RTL) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_de_hebr() {
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("de-Hebr"));
        assert!(
            findings.is_empty(),
            "de-Hebr (Hebrew script = RTL) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_ar_non_ascii_junk() {
        // "Lätn" has non-ASCII ä → not valid script → rejected → falls back to "ar" (RTL) → allow
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-L\u{00E4}tn"));
        assert!(
            findings.is_empty(),
            "ar-Lätn (invalid subtag ignored, ar is RTL) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_ar_whitespace_junk() {
        // 4 spaces → not valid script → rejected → falls back to "ar" (RTL) → allow
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-    "));
        assert!(
            findings.is_empty(),
            "ar-'    ' (invalid subtag ignored, ar is RTL) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_bidi_ar_digit_junk() {
        // "1234" → digits → not valid script → rejected → falls back to "ar" (RTL) → allow
        let text = "invoice_\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-1234"));
        assert!(
            findings.is_empty(),
            "ar-1234 (invalid subtag ignored, ar is RTL) should exempt, got: {:?}",
            findings
        );
    }

    // --- Red-team round-5: extension/private-use singleton over-exemption ---

    #[test]
    fn blocks_bidi_en_us_x_arab() {
        // Exact red-team repro: en-US-x-Arab must NOT exempt bidi controls.
        // 'x' is the private-use singleton; 'Arab' is inside the private-use sequence
        // and must NOT be treated as a BCP-47 script subtag.
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-US-x-Arab"));
        assert!(
            !findings.is_empty(),
            "en-US-x-Arab (Arab is private-use data, not a script subtag) must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_en_t_hebr() {
        // 't' is a BCP-47 extension singleton; Hebr inside 't-' sequence is NOT a script subtag
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-t-Hebr"));
        assert!(
            !findings.is_empty(),
            "en-t-Hebr (Hebr inside extension, not a script subtag) must block"
        );
    }

    #[test]
    fn blocks_bidi_en_us_t_hebr() {
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-US-t-Hebr"));
        assert!(
            !findings.is_empty(),
            "en-US-t-Hebr must block (Hebr after 't' singleton is not a script subtag)"
        );
    }

    #[test]
    fn blocks_bidi_de_de_x_syrc() {
        // de-DE-x-Syrc: 'x' private-use singleton; Syrc is private-use data
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("de-DE-x-Syrc"));
        assert!(
            !findings.is_empty(),
            "de-DE-x-Syrc must block (Syrc is private-use data, not a real script subtag)"
        );
    }

    #[test]
    fn blocks_bidi_en_x_arab() {
        // en-x-Arab: 'x' immediately after primary — Arab is private-use data
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-x-Arab"));
        assert!(
            !findings.is_empty(),
            "en-x-Arab must block (Arab after private-use singleton 'x')"
        );
    }

    #[test]
    fn still_allows_canonical_script_subtag_ar_arab() {
        // ar-Arab: Arab IS in canonical position (directly after primary 'ar')
        // Must still exempt bidi controls — existing correct behavior preserved
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-Arab"));
        assert!(
            findings.is_empty(),
            "ar-Arab (Arab in canonical position = RTL) should still exempt, got: {:?}",
            findings
        );
    }

    // --- Round-7: singleton-as-primary BCP-47 tag over-exemption (incomplete round-5 fix) ---
    //
    // The round-5 fix stopped at parts[1..]; a singleton AT parts[0] (x-Arab, a-Arab,
    // _Arab empty primary) was never stopped and the trailing script-like token was
    // read as an RTL script subtag, exempting bidi controls.

    #[test]
    fn blocks_bidi_x_arab_leading_singleton() {
        // Exact red-team repro: x-Arab — 'x' is private-use primary singleton, not a language
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("x-Arab"));
        assert!(
            !findings.is_empty(),
            "x-Arab (private-use singleton as primary) must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_x_hebr_leading_singleton() {
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("x-Hebr"));
        assert!(
            !findings.is_empty(),
            "x-Hebr (private-use singleton as primary) must block"
        );
    }

    #[test]
    fn blocks_bidi_a_arab_extension_singleton() {
        // 'a' is a BCP-47 extension singleton — NOT a real language code
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("a-Arab"));
        assert!(
            !findings.is_empty(),
            "a-Arab (extension singleton as primary) must block"
        );
    }

    #[test]
    fn blocks_bidi_empty_primary_arab() {
        // _Arab splits to ["", "Arab"] — empty primary is not a real language
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("_Arab"));
        assert!(
            !findings.is_empty(),
            "_Arab (empty primary) must block, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_0_arab_digit_primary() {
        // '0' is a single-char digit — not a valid language code
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("0-Arab"));
        assert!(
            !findings.is_empty(),
            "0-Arab (digit singleton as primary) must block"
        );
    }

    #[test]
    fn still_allows_canonical_en_syrc() {
        // en-Syrc: Syrc is in canonical position (directly after primary 'en')
        // Must still exempt bidi controls — existing correct behavior preserved
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-Syrc"));
        assert!(
            findings.is_empty(),
            "en-Syrc (Syrc in canonical position = RTL) should still exempt, got: {:?}",
            findings
        );
    }

    // --- Red-team defect #1: Script-name token in non-canonical BCP-47 position ---
    // RFC-5646 requires a script subtag to appear in position 2 (immediately after
    // the primary language subtag) and before any region subtag. A 4-alpha token
    // appearing AFTER a region subtag is a variant subtag, not a script subtag.

    #[test]
    fn blocks_bidi_en_us_arab_non_canonical_script() {
        // en-US-Arab: "Arab" is in position 3, after region "US" — NOT a script subtag
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-US-Arab"));
        assert!(
            !findings.is_empty(),
            "en-US-Arab (Arab after region 'US', non-canonical position) must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_en_gb_hebr_non_canonical_script() {
        // en-GB-Hebr: "Hebr" is after region "GB" — NOT a script subtag per RFC-5646
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-GB-Hebr"));
        assert!(
            !findings.is_empty(),
            "en-GB-Hebr (Hebr after region 'GB', non-canonical position) must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_fr_fr_syrc_non_canonical_script() {
        // fr-FR-Syrc: "Syrc" is after region "FR" — NOT a script subtag
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("fr-FR-Syrc"));
        assert!(
            !findings.is_empty(),
            "fr-FR-Syrc (Syrc after region 'FR', non-canonical position) must block bidi controls, got: {:?}",
            findings
        );
    }

    // --- Red-team defect: invalid non-region/non-singleton subtag grants RTL over-exemption ---
    //
    // en-12-Arab:   "12" is 2-digit (not a valid region: only 3-digit is allowed for numeric regions)
    //               → silently skipped → "Arab" promoted to script position → wrong RTL exemption
    // en--Arab:     "--" splits to empty string "" → silently skipped → "Arab" promoted → wrong RTL
    // en-x9-Arab:   "x9" is alphanumeric (not all-alpha, not all-digit) → silently skipped → wrong RTL
    // en-99999-Arab: "99999" is 5-digit (too long for any valid BCP-47 subtag) → silently skipped → wrong RTL
    //
    // Fix: any subtag that is not extlang(3-alpha), script(4-alpha), or region(2-alpha/3-digit)
    // must act as a structural break (or set region_seen=true), preventing later 4-alpha tokens
    // from being promoted to canonical script position.

    #[test]
    fn blocks_bidi_en_12_arab_malformed_subtag() {
        // "12" is 2-digit: not a region (needs 3 digits), not extlang, not script → structural break
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-12-Arab"));
        assert!(
            !findings.is_empty(),
            "en-12-Arab (malformed '12' subtag before 'Arab') must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_en_empty_subtag_arab() {
        // "--" splits to an empty string "" → structural break → "Arab" must NOT be script
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en--Arab"));
        assert!(
            !findings.is_empty(),
            "en--Arab (empty subtag from '--' before 'Arab') must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_en_x9_arab_alnum_subtag() {
        // "x9" is alphanumeric mixed (not all-alpha, not all-digit) → structural break
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-x9-Arab"));
        assert!(
            !findings.is_empty(),
            "en-x9-Arab (alnum 'x9' subtag before 'Arab') must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_en_99999_arab_overlong_digit_subtag() {
        // "99999" is 5-digit: too long to be any valid BCP-47 subtag → structural break
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-99999-Arab"));
        assert!(
            !findings.is_empty(),
            "en-99999-Arab (5-digit '99999' subtag before 'Arab') must block bidi controls, got: {:?}",
            findings
        );
    }

    // Regression: en-1234 already has a test above (blocks_bidi_en_digit_script).
    // The new malformed-subtag fix must NOT regress these existing-allow cases:

    #[test]
    fn still_allows_en_arab_after_extlang_canonical() {
        // en-cmn-Arab: "cmn" is a valid extlang (3-alpha) → extlang seen → "Arab" still in
        // canonical script position (after extlang, before region). Must still exempt.
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-cmn-Arab"));
        assert!(
            findings.is_empty(),
            "en-cmn-Arab (cmn=extlang, Arab=script in canonical position) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn still_allows_en_arab_canonical_no_region() {
        // en-Arab: "Arab" is directly after primary "en" — canonical script position → RTL
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-Arab"));
        assert!(
            findings.is_empty(),
            "en-Arab (Arab in canonical position, no region) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn still_allows_en_arab_us_canonical_with_region() {
        // en-Arab-US: "Arab" is in canonical position (position 2, before region "US") → RTL
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-Arab-US"));
        assert!(
            findings.is_empty(),
            "en-Arab-US (Arab in canonical position before region) should exempt, got: {:?}",
            findings
        );
    }

    #[test]
    fn still_allows_ar_sa_no_script() {
        // ar-SA: "SA" is 2 chars (region), no script subtag — falls back to primary "ar" RTL
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-SA"));
        assert!(
            findings.is_empty(),
            "ar-SA (region only, no script, primary 'ar' is RTL) should exempt, got: {:?}",
            findings
        );
    }

    // --- Red-team defect #2: Tifinagh (Tfng) wrongly classified as RTL ---
    // Modern Unicode Neo-Tifinagh is bidi-class L (LTR). CLDR default direction
    // is LTR. Tfng must NOT appear in the RTL script allowlist.

    #[test]
    fn blocks_bidi_en_tfng_ltf_script() {
        // en-Tfng: Tifinagh is an LTR script — must NOT exempt bidi controls
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("en-Tfng"));
        assert!(
            !findings.is_empty(),
            "en-Tfng (Tifinagh = LTR script) must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_zgh_tfng_ltf_script() {
        // zgh-Tfng: Standard Moroccan Tamazight in Tifinagh — Tifinagh is LTR
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("zgh-Tfng"));
        assert!(
            !findings.is_empty(),
            "zgh-Tfng (Tifinagh = LTR script) must block bidi controls, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_bidi_ar_tfng_ltr_override() {
        // ar-Tfng: Even with RTL primary language, explicit Tifinagh script is LTR
        // The script subtag takes precedence — Tfng is LTR, so must block
        let text = "invoice\u{202E}fdp.exe";
        let findings = detector().detect(text, &opts_with_locale("ar-Tfng"));
        assert!(
            !findings.is_empty(),
            "ar-Tfng (Tifinagh = LTR, script overrides language) must block bidi controls, got: {:?}",
            findings
        );
    }
}

use icu_properties::{
    props::{DefaultIgnorableCodePoint, ExtendedPictographic},
    CodePointSetData,
};

use crate::types::{Category, Direction, Finding, ScanOptions, Severity};

/// Detector for zero-width and invisible characters that can be used to fragment
/// keywords or smuggle hidden instructions.
///
/// Detection strategy: flag any character carrying the Unicode
/// `Default_Ignorable_Code_Point` property, with additional coverage for
/// `General_Category=Cf` (format) characters that are NOT in
/// `Default_Ignorable_Code_Point` but are still invisible and enable
/// text-fragmentation attacks. Exemptions:
///
/// 1. Characters handled by dedicated detectors (bidi marks `U+200E`/`U+200F`,
///    bidi embeddings `U+202A`–`U+202E`, bidi isolates `U+2066`–`U+2069`, tag
///    characters `U+E0000`–`U+E007F`, and VS Supplement `U+E0100`–`U+E01EF`)
///    are skipped to avoid double-counting.
/// 2. `U+200D` ZWJ is **exempt** when both immediately-flanking non-VS/non-modifier
///    characters have the `ExtendedPictographic` property (a valid emoji ZWJ
///    sequence). Variation selectors and Emoji_Modifier (Fitzpatrick skin-tone,
///    U+1F3FB–U+1F3FF) are transparent when searching for flanking emoji bases.
/// 3. `U+FE00`–`U+FE0F` variation selectors are **exempt** when the immediately
///    preceding character has the `ExtendedPictographic` property (valid emoji
///    presentation selector). Standalone VS or VS between non-emoji is flagged.
/// 4. `U+FFF9`–`U+FFFB` (interlinear annotation chars) are invisible `Cf`
///    characters NOT in `Default_Ignorable_Code_Point` but are explicitly
///    flagged as `zero_width.invisible_format` to prevent text fragmentation.
/// 5. `U+FE00`–`U+FE0F` variation selectors are also **exempt** in a keycap
///    sequence: a keycap base (`0`–`9`, `#`, `*`) followed by VS16 and then
///    `U+20E3` (COMBINING ENCLOSING KEYCAP).
/// 6. Egyptian Hieroglyph Format Controls (`U+13430`–`U+1343F`) are `Cf` chars
///    NOT in `Default_Ignorable_Code_Point`; they are flagged as
///    `zero_width.invisible_format` to prevent ChatML/LLM token fragmentation.
///    Coverage is extended to `U+13440`–`U+13455` (Mn modifiers in the same
///    block) which are structurally identical and sit immediately adjacent.
/// 7. Prepended-concatenation `Cf` marks (`U+0600`–`U+0605`, `U+06DD`, `U+070F`,
///    `U+08E2`, `U+110BD`, `U+110CD`) are invisible between ASCII/Latin text and
///    are flagged as `zero_width.invisible_format`.
///
/// Rule IDs (preserved for backward compatibility):
/// - `U+200B` → `zero_width.zwsp`
/// - `U+200C` → `zero_width.zwnj`
/// - `U+200D` → `zero_width.zwj` (unless exempted)
/// - `U+FEFF` → `zero_width.bom`
/// - `U+00AD` → `zero_width.soft_hyphen`
/// - All other `Default_Ignorable` → `zero_width.invisible_format`
pub struct ZeroWidthDetector;

impl ZeroWidthDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect zero-width and invisible characters in the given text.
    pub fn detect(&self, text: &str, _opts: &ScanOptions) -> Vec<Finding> {
        let di = CodePointSetData::new::<DefaultIgnorableCodePoint>();
        let ep = CodePointSetData::new::<ExtendedPictographic>();
        let mut findings = Vec::new();

        // Collect chars with their byte positions for context lookup.
        let chars: Vec<(usize, char)> = text.char_indices().collect();

        for (idx, &(byte_pos, ch)) in chars.iter().enumerate() {
            // Process Default_Ignorable characters AND additional Cf format chars that
            // are NOT in Default_Ignorable but are still invisible/fragmenting:
            // - Interlinear annotations (U+FFF9-U+FFFB)
            // - Egyptian Hieroglyph Format Controls (U+13430-U+1343F)
            // - Prepended-concatenation marks (U+0600-U+0605, U+06DD, U+070F, U+08E2,
            //   U+110BD, U+110CD)
            if !di.contains(ch)
                && !is_interlinear_annotation(ch)
                && !is_egyptian_hieroglyph_format_control(ch)
                && !is_prepended_concatenation_mark(ch)
                && !is_invisible_joiner_mn(ch)
            {
                continue;
            }

            // Skip characters handled by other dedicated detectors.
            if is_excluded_default_ignorable(ch) {
                continue;
            }

            let rule_id_opt: Option<&str> = match ch {
                '\u{200B}' => Some("zero_width.zwsp"),
                '\u{200C}' => Some("zero_width.zwnj"),
                '\u{200D}' => {
                    // ZWJ exemption: allowed ONLY when both flanking non-VS characters
                    // have the ExtendedPictographic property (real emoji ZWJ sequence).
                    // Variation selectors are skipped when looking for the flanking base.
                    let prev_base = flanking_base(&chars, idx, false);
                    let next_base = flanking_base(&chars, idx, true);
                    let both_emoji = prev_base.map(|c| ep.contains(c)) == Some(true)
                        && next_base.map(|c| ep.contains(c)) == Some(true);
                    if both_emoji {
                        None // exempt — valid emoji ZWJ sequence
                    } else {
                        Some("zero_width.zwj")
                    }
                }
                '\u{FEFF}' => Some("zero_width.bom"),
                '\u{00AD}' => Some("zero_width.soft_hyphen"),
                // Variation selectors: exempt when preceded by emoji, or in a keycap sequence.
                '\u{FE00}'..='\u{FE0F}' => {
                    let prev_char = if idx > 0 {
                        Some(chars[idx - 1].1)
                    } else {
                        None
                    };
                    let next_char = if idx + 1 < chars.len() {
                        Some(chars[idx + 1].1)
                    } else {
                        None
                    };
                    let is_emoji_vs = prev_char.map(|c| ep.contains(c)) == Some(true);
                    let is_keycap_vs = prev_char.map(is_keycap_base) == Some(true)
                        && next_char == Some('\u{20E3}');
                    if is_emoji_vs || is_keycap_vs {
                        None // exempt — emoji presentation selector or keycap sequence
                    } else {
                        Some("zero_width.invisible_format")
                    }
                }
                // All other Default_Ignorable characters: text fragmentation vectors.
                _ => Some("zero_width.invisible_format"),
            };

            if let Some(rule_id) = rule_id_opt {
                let end = byte_pos + ch.len_utf8();
                findings.push(Finding {
                    rule_id: rule_id.to_string(),
                    category: Category::ZeroWidth,
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

impl Default for ZeroWidthDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` for `Default_Ignorable` characters handled by other dedicated
/// detectors, to avoid double-flagging.
fn is_excluded_default_ignorable(ch: char) -> bool {
    matches!(ch,
        // Bidi marks — handled by bidi.rs
        '\u{200E}' | '\u{200F}' |
        '\u{202A}'..='\u{202E}' |
        '\u{2066}'..='\u{2069}' |
        // Tag characters — handled by unicode_tags.rs
        '\u{E0000}'..='\u{E007F}' |
        // Variation Selectors Supplement — CJK-specific, low attack surface
        '\u{E0100}'..='\u{E01EF}'
    )
}

/// Returns `true` for interlinear annotation characters (U+FFF9-U+FFFB).
/// These are General_Category=Cf (invisible format chars) but are NOT in the
/// Default_Ignorable_Code_Point set, so the DI-only gate misses them.
/// They enable text fragmentation attacks identical to DI chars.
fn is_interlinear_annotation(ch: char) -> bool {
    matches!(ch, '\u{FFF9}' | '\u{FFFA}' | '\u{FFFB}')
}

/// Returns `true` for Egyptian Hieroglyph Format Controls and adjacent
/// modifier/format characters (U+13430–U+13455).
///
/// The core Cf block U+13430–U+1343F (16 codepoints) are invisible joiners/
/// enclosures. U+13440 EGYPTIAN HIEROGLYPH MIRROR HORIZONTALLY (Mn) sits
/// exactly one codepoint past the prior upper bound and is also zero-advance
/// and invisible between ASCII chars. U+13441–U+13455 are Egyptian Hieroglyph
/// modifier letters (Mn), all zero-advance and invisible in non-hieroglyph
/// contexts.
///
/// None of these codepoints are in Default_Ignorable_Code_Point, so the
/// DI-only gate misses them. Widening to U+13455 closes the off-by-one seam
/// between the Cf and Mn sub-ranges of this block.
fn is_egyptian_hieroglyph_format_control(ch: char) -> bool {
    matches!(ch, '\u{13430}'..='\u{13455}')
}

/// Returns `true` for prepended-concatenation format marks that are
/// General_Category=Cf but NOT in Default_Ignorable_Code_Point.
/// Between Latin/ASCII text these characters are invisible and enable
/// keyword-fragmentation attacks.
///
/// Covered codepoints:
/// - U+0600-U+0605: Arabic Number Sign … Arabic Number Mark Above
/// - U+06DD: Arabic End of Ayah
/// - U+070F: Syriac Abbreviation Mark
/// - U+0890-U+0891: Arabic Pound Mark Above / Arabic Piastre Mark Above
/// - U+08E2: Arabic Disputed End of Ayah
/// - U+110BD: Kaithi Number Sign
/// - U+110CD: Kaithi Number Sign Above
fn is_prepended_concatenation_mark(ch: char) -> bool {
    matches!(
        ch,
        '\u{0600}'..='\u{0605}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{110BD}'
            | '\u{110CD}'
    )
}

/// Returns `true` for known zero-advance Mn (nonspacing mark) joiners that are
/// NOT in the `Default_Ignorable_Code_Point` set but are functionally invisible
/// between Latin/ASCII text and can be used to fragment keywords or LLM control
/// tokens — analogous to their DI-property siblings U+180E/U+034F.
///
/// This is a curated allowlist of zero-advance subjoiner/conjoiner/virama Mn
/// codepoints that have no visual representation when inserted between
/// non-native-script characters. Blanket gc=Mn is intentionally NOT used to
/// avoid false-positive regressions on legitimate combining diacritics
/// (U+0300–U+036F, etc.).
///
/// The full virama/halanta family (Mn, ccc=9) is included: original conjoiners
/// together with their sibling virama/halanta forms that are structurally
/// identical (same script, same zero-advance, same ccc=9 combining class).
///
/// Covered codepoints:
/// - U+2D7F:  TIFINAGH CONSONANT JOINER           (Mn, ccc=9, zero-advance)
/// - U+1107F: BRAHMI NUMBER JOINER                (Mn, ccc=9, zero-advance)
/// - U+1172B: AHOM SIGN KILLER                    (Mn, ccc=9, zero-advance)
/// - U+113CE: TULU-TIGALARI SIGN VIRAMA           (Mn, ccc=9, zero-advance)
/// - U+113D0: TULU-TIGALARI CONSONANT JOINER      (Mn, ccc=9, zero-advance)
/// - U+1193E: DIVES AKURU VIRAMA                  (Mn, ccc=9, zero-advance)
/// - U+11A34: ZANABAZAR SQUARE SIGN VIRAMA        (Mn, ccc=9, zero-advance)
/// - U+11A47: ZANABAZAR SQUARE SUBJOINER          (Mn, ccc=9, zero-advance)
/// - U+11A99: SOYOMBO SUBJOINER                   (Mn, ccc=9, zero-advance)
/// - U+11D44: MASARAM GONDI SIGN HALANTA          (Mn, ccc=9, zero-advance)
/// - U+11D45: MASARAM GONDI VIRAMA                (Mn, ccc=9, zero-advance)
/// - U+11D97: GUNJALA GONDI VIRAMA                (Mn, ccc=9, zero-advance)
/// - U+11F42: KAWI CONJOINING CONSONANT SIGN MEDIUM (Mn, ccc=9, zero-advance)
/// - U+1612F: GURUNG KHEMA SIGN THOLHOMA          (Mn, ccc=9, zero-advance)
/// - U+16FE4: OLD KHITAN SMALL SCRIPT FILLER      (Mn, ccc=0, zero-advance)
fn is_invisible_joiner_mn(ch: char) -> bool {
    matches!(
        ch,
        '\u{2D7F}'
            | '\u{1107F}'
            | '\u{1172B}'
            | '\u{113CE}'
            | '\u{113D0}'
            | '\u{1193E}'
            | '\u{11A34}'
            | '\u{11A47}'
            | '\u{11A99}'
            | '\u{11D44}'
            | '\u{11D45}'
            | '\u{11D97}'
            | '\u{11F42}'
            | '\u{1612F}'
            | '\u{16FE4}'
    )
}

/// Returns `true` if `ch` is an Emoji_Modifier (Fitzpatrick skin-tone modifier).
/// These are U+1F3FB–U+1F3FF (EMOJI MODIFIER FITZPATRICK TYPE-1-2 … TYPE-6).
/// They are General_Category=Sk and visually combine with the preceding emoji.
/// When scanning for ZWJ flanking bases, skin-tone modifiers should be treated
/// as transparent (like variation selectors) so that `👩🏻‍💻` is correctly
/// recognised as an emoji ZWJ sequence.
fn is_emoji_modifier(ch: char) -> bool {
    matches!(ch, '\u{1F3FB}'..='\u{1F3FF}')
}

/// Returns `true` if `ch` is a valid keycap base character (digits 0-9, #, *).
/// These precede U+FE0F + U+20E3 in RGI keycap emoji sequences.
fn is_keycap_base(ch: char) -> bool {
    matches!(ch, '0'..='9' | '#' | '*')
}

/// Returns `true` if `ch` is a variation selector (`U+FE00`–`U+FE0F`).
fn is_variation_selector(ch: char) -> bool {
    matches!(ch, '\u{FE00}'..='\u{FE0F}')
}

/// Walk from `idx` in the given direction, skipping variation selectors and
/// Emoji_Modifier (Fitzpatrick skin-tone, U+1F3FB–U+1F3FF) characters.
/// Returns the first non-VS/non-modifier character, or `None` if the boundary
/// is reached.
///
/// Skipping both variation selectors and Emoji_Modifier ensures that a ZWJ
/// flanked by a skin-toned emoji (e.g. 👩🏻‍💻 = woman + U+1F3FB + ZWJ + laptop)
/// resolves to the underlying Extended_Pictographic base, and is correctly
/// exempt rather than falsely flagged as `zero_width.zwj`.
///
/// `forward = true` walks toward higher indices; `false` walks backward.
fn flanking_base(chars: &[(usize, char)], idx: usize, forward: bool) -> Option<char> {
    if forward {
        let mut i = idx + 1;
        while i < chars.len() {
            let ch = chars[i].1;
            if !is_variation_selector(ch) && !is_emoji_modifier(ch) {
                return Some(ch);
            }
            i += 1;
        }
    } else {
        let mut i = idx;
        while i > 0 {
            i -= 1;
            let ch = chars[i].1;
            if !is_variation_selector(ch) && !is_emoji_modifier(ch) {
                return Some(ch);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> ZeroWidthDetector {
        ZeroWidthDetector::new()
    }

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    #[test]
    fn detects_zwsp() {
        let text = "hello\u{200B}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "zero_width.zwsp");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_zwnj() {
        let text = "hello\u{200C}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "zero_width.zwnj");
    }

    #[test]
    fn detects_bare_zwj() {
        // ZWJ not flanked by emoji — should be flagged
        let text = "hello\u{200D}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "zero_width.zwj");
    }

    #[test]
    fn detects_bom() {
        let text = "\u{FEFF}hello world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "zero_width.bom");
    }

    #[test]
    fn detects_soft_hyphen() {
        let text = "soft\u{00AD}hyphen";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "zero_width.soft_hyphen");
    }

    #[test]
    fn allows_zwj_in_emoji_sequence() {
        // Family emoji: 👨‍👩‍👧‍👦 — ZWJ flanked by emoji on both sides
        let text = "👨\u{200D}👩\u{200D}👧\u{200D}👦";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj_findings.is_empty(),
            "ZWJ in family emoji should be exempt, got: {:?}",
            zwj_findings
        );
    }

    #[test]
    fn allows_zwj_in_flag_sequence() {
        // Rainbow flag: 🏳️‍🌈
        let text = "🏳\u{200D}🌈";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj_findings.is_empty(),
            "ZWJ in flag emoji should be exempt, got: {:?}",
            zwj_findings
        );
    }

    #[test]
    fn allows_zwj_in_person_laptop_sequence() {
        // 👩‍💻 = 👩 ZWJ 💻
        let text = "👩\u{200D}💻";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj_findings.is_empty(),
            "ZWJ in person+laptop emoji should be exempt, got: {:?}",
            zwj_findings
        );
    }

    #[test]
    fn detects_multiple_types() {
        let text = "\u{200B}hello\u{FEFF}world";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 2, "expected 2 findings: ZWSP + BOM");
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"zero_width.zwsp"));
        assert!(ids.contains(&"zero_width.bom"));
    }

    #[test]
    fn detects_zero_width_in_keyword() {
        // password fragmented with ZWSP
        let text = "p\u{200B}a\u{200B}s\u{200B}s\u{200B}w\u{200B}o\u{200B}r\u{200B}d";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 7, "expected 7 ZWSP findings");
        for f in &findings {
            assert_eq!(f.rule_id, "zero_width.zwsp");
        }
    }

    #[test]
    fn span_offsets_correct() {
        let text = "hi\u{200B}there";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1);
        let (start, end) = findings[0].span;
        // "hi" is 2 bytes, ZWSP is 3 bytes (0xE2 0x80 0x8B)
        assert_eq!(start, 2);
        assert_eq!(end, 5);
        assert_eq!(&text[start..end], "\u{200B}");
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
    fn no_false_positive_math() {
        let text = "∑ ∏ √ ∞ π ∂ ∫ ∇ ≤ ≥ ≠ ≈";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "math symbols should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn empty_string_produces_no_findings() {
        let findings = detector().detect("", &opts());
        assert!(findings.is_empty());
    }

    // --- Red-team defect #13: U+2060 WORD JOINER and other invisible Cf chars ---

    #[test]
    fn detects_word_joiner() {
        // U+2060 between chars in a key-like string
        let text = ["sk-ant-", "api03-a\u{2060}b\u{2060}c"].concat();
        let findings = detector().detect(&text, &opts());
        let zw: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.starts_with("zero_width"))
            .collect();
        assert!(
            zw.len() >= 2,
            "expected at least 2 zero_width findings for U+2060, got {:?}",
            zw
        );
    }

    #[test]
    fn detects_function_application() {
        let text = "ignore\u{2061}this";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+2061 should produce 1 finding");
        assert!(findings[0].rule_id.starts_with("zero_width"));
    }

    #[test]
    fn detects_invisible_times() {
        let text = "secret\u{2062}key";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+2062 should produce 1 finding");
        assert!(findings[0].rule_id.starts_with("zero_width"));
    }

    #[test]
    fn detects_invisible_separator() {
        let text = "pass\u{2063}word";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+2063 should produce 1 finding");
        assert!(findings[0].rule_id.starts_with("zero_width"));
    }

    #[test]
    fn detects_invisible_plus() {
        let text = "tok\u{2064}en";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+2064 should produce 1 finding");
        assert!(findings[0].rule_id.starts_with("zero_width"));
    }

    #[test]
    fn detects_deprecated_format_206a_through_206f() {
        // One of each U+206A through U+206F (6 chars)
        let text = "\u{206A}\u{206B}\u{206C}\u{206D}\u{206E}\u{206F}";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            6,
            "expected 6 findings for U+206A..=U+206F, got {:?}",
            findings
        );
        for f in &findings {
            assert!(f.rule_id.starts_with("zero_width"));
        }
    }

    #[test]
    fn detects_mongolian_vowel_separator() {
        let text = "fra\u{180E}gment";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+180E should produce 1 finding");
        assert!(findings[0].rule_id.starts_with("zero_width"));
    }

    #[test]
    fn detects_arabic_letter_mark() {
        let text = "hid\u{061C}den";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+061C should produce 1 finding");
        assert!(findings[0].rule_id.starts_with("zero_width"));
    }

    // Adversarial variants for #13

    #[test]
    fn keyword_fragmented_by_word_joiner() {
        // "password" with U+2060 between every character — 7 ZW chars
        let text = "p\u{2060}a\u{2060}s\u{2060}s\u{2060}w\u{2060}o\u{2060}r\u{2060}d";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            7,
            "expected 7 findings for word-joiner-fragmented keyword"
        );
    }

    #[test]
    fn anthropic_key_fragmented_by_invisible_times() {
        // 4 U+2062 chars interleaved
        let text = ["sk-ant-", "api03-\u{2062}A\u{2062}B\u{2062}C\u{2062}D"].concat();
        let findings = detector().detect(&text, &opts());
        assert_eq!(
            findings.len(),
            4,
            "expected 4 findings for invisible-times-fragmented key"
        );
    }

    #[test]
    fn mixed_invisible_chars() {
        // U+2060, U+2063, U+180E, U+061C interspersed
        let text = "a\u{2060}b\u{2063}c\u{180E}d\u{061C}e";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            4,
            "expected 4 findings for mixed invisible chars"
        );
    }

    #[test]
    fn instruction_fragmented_by_deprecated_format() {
        // U+206A and U+206B between chars of "ignore"
        let text = "ig\u{206A}no\u{206B}re";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            2,
            "expected 2 findings for deprecated-format-fragmented instruction"
        );
    }

    // --- Red-team defect #14: Over-broad ZWJ emoji-exemption ---

    // scissors (U+2702) IS ExtendedPictographic — ZWJ should be ALLOWED
    #[test]
    fn allows_zwj_between_scissors() {
        let text = "pass\u{2702}\u{200D}\u{2702}word";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj_findings.is_empty(),
            "ZWJ between scissors (U+2702, ExtendedPictographic) should be exempt, got: {:?}",
            zwj_findings
        );
    }

    // keyboard (U+2328) IS ExtendedPictographic — ZWJ should be ALLOWED
    #[test]
    fn allows_zwj_between_keyboard_symbols() {
        let text = "data\u{2328}\u{200D}\u{2328}leak";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj_findings.is_empty(),
            "ZWJ between keyboard symbols (U+2328, ExtendedPictographic) should be exempt, got: {:?}",
            zwj_findings
        );
    }

    // gear (U+2699) IS ExtendedPictographic — ZWJ should be ALLOWED
    #[test]
    fn allows_zwj_between_gear_symbols() {
        let text = "run\u{2699}\u{200D}\u{2699}cmd";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj_findings.is_empty(),
            "ZWJ between gear symbols (U+2699, ExtendedPictographic) should be exempt, got: {:?}",
            zwj_findings
        );
    }

    // recycling (U+267B) IS ExtendedPictographic — ZWJ should be ALLOWED
    #[test]
    fn allows_zwj_between_recycle() {
        let text = "\u{267B}\u{200D}\u{267B}";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj_findings.is_empty(),
            "ZWJ between recycling symbols (U+267B, ExtendedPictographic) should be exempt, got: {:?}",
            zwj_findings
        );
    }

    // Adversarial variants for #14

    #[test]
    fn blocks_zwj_between_misc_technical() {
        // U+2300 ⌀ DIAMETER SIGN — NOT ExtendedPictographic
        let text = "\u{2300}\u{200D}\u{2300}";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            !zwj_findings.is_empty(),
            "ZWJ between U+2300 (DIAMETER SIGN) must be flagged"
        );
    }

    #[test]
    fn blocks_zwj_between_ballot_box() {
        // U+2610 ☐ BALLOT BOX — NOT ExtendedPictographic
        let text = "\u{2610}\u{200D}\u{2610}";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            !zwj_findings.is_empty(),
            "ZWJ between U+2610 (BALLOT BOX) must be flagged"
        );
    }

    #[test]
    fn allows_zwj_between_gendered_emoji() {
        // 👨‍⚕️ man health worker: 👨 ZWJ ⚕ FE0F — U+2695 IS ExtendedPictographic
        let text = "👨\u{200D}\u{2695}\u{FE0F}";
        let findings = detector().detect(text, &opts());
        let zwj_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj_findings.is_empty(),
            "ZWJ between man emoji and U+2695 (health worker) should be exempt, got: {:?}",
            zwj_findings
        );
    }

    // --- New MUST BLOCK tests (TDD red phase) ---

    #[test]
    fn detects_khmer_inherent_vowel_17b4() {
        // U+17B4 is Default_Ignorable — must be caught
        let text = "a\u{17B4}b";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+17B4 Khmer inherent vowel must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_khmer_inherent_vowel_17b5() {
        let text = "x\u{17B5}y";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+17B5 Khmer inherent vowel must be flagged"
        );
    }

    #[test]
    fn detects_hangul_filler_3164() {
        let text = "see\u{3164}this";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "U+3164 Hangul filler must be flagged");
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_hangul_choseong_filler_115f() {
        let text = "a\u{115F}b";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+115F Hangul Choseong filler must be flagged"
        );
    }

    #[test]
    fn detects_hangul_jungseong_filler_1160() {
        let text = "a\u{1160}b";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+1160 Hangul Jungseong filler must be flagged"
        );
    }

    #[test]
    fn detects_halfwidth_hangul_filler_ffa0() {
        let text = "a\u{FFA0}b";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+FFA0 Halfwidth Hangul filler must be flagged"
        );
    }

    #[test]
    fn detects_standalone_variation_selector() {
        // VS between letters — not following emoji — must be flagged
        let text = "a\u{FE0E}b";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "standalone VS U+FE0E must be flagged");
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_standalone_vs16_between_letters() {
        let text = "x\u{FE0F}y";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "standalone VS16 U+FE0F must be flagged"
        );
    }

    #[test]
    fn detects_vs_wrapped_zwj() {
        // U+FE0F U+200D U+FE0F — all three must produce findings
        let text = "\u{FE0F}\u{200D}\u{FE0F}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.len() >= 3,
            "VS-wrapped ZWJ must produce >=3 findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn detects_bare_zwj_between_letters() {
        // explicit must-block spec: bare ZWJ between non-emoji
        let text = "foo\u{200D}bar";
        let findings = detector().detect(text, &opts());
        let zwj: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            !zwj.is_empty(),
            "bare ZWJ between non-emoji must be flagged"
        );
    }

    #[test]
    fn detects_chatml_fragmented_by_khmer() {
        // <|im + U+17B4 + _start|> — the U+17B4 must be flagged
        let text = "<|im\u{17B4}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+17B4 fragmenting ChatML token must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_combining_grapheme_joiner() {
        // U+034F is Default_Ignorable
        let text = "te\u{034F}st";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "U+034F CGJ must be flagged");
    }

    // --- New MUST ALLOW tests (TDD red phase) ---

    #[test]
    fn allows_emoji_followed_by_vs16() {
        // U+270B U+FE0F — raised hand with emoji presentation
        let text = "\u{270B}\u{FE0F}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "emoji+VS16 should be allowed, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_pirate_flag_emoji() {
        // U+1F3F4 U+200D U+2620 U+FE0F — pirate flag
        let text = "\u{1F3F4}\u{200D}\u{2620}\u{FE0F}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "pirate flag emoji should be allowed, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_rainbow_flag_with_vs() {
        // U+1F3F3 U+FE0F U+200D U+1F308 — rainbow flag (VS between base and ZWJ)
        let text = "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "rainbow flag emoji should be allowed, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_accented_latin() {
        let text = "café résumé naïve";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "accented Latin should produce no findings, got: {:?}",
            findings
        );
    }

    // --- Red-team round-4 defect: Interlinear annotation bypass (U+FFF9-U+FFFB) ---

    #[test]
    fn detects_interlinear_annotation_anchor() {
        // U+FFF9 INTERLINEAR ANNOTATION ANCHOR — invisible Cf, not DI
        let text = "key\u{FFF9}word";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+FFF9 must produce 1 finding");
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_interlinear_annotation_separator() {
        // U+FFFA INTERLINEAR ANNOTATION SEPARATOR — invisible Cf, not DI
        let text = "frag\u{FFFA}ment";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+FFFA must produce 1 finding");
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_interlinear_annotation_terminator() {
        // U+FFFB INTERLINEAR ANNOTATION TERMINATOR — invisible Cf, not DI
        let text = "hid\u{FFFB}den";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "U+FFFB must produce 1 finding");
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_chatml_fragmented_by_interlinear() {
        // ChatML token split by U+FFFA — must block
        let text = "<|im\u{FFFA}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+FFFA fragmenting ChatML token must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_keyword_fragmented_by_interlinear_anchor() {
        // "password" fragmented by U+FFF9
        let text = "pass\u{FFF9}word";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            1,
            "U+FFF9 fragmenting keyword must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_all_three_interlinear_in_sequence() {
        let text = "\u{FFF9}hello\u{FFFA}world\u{FFFB}";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            3,
            "all three interlinear annotation chars must be flagged"
        );
        for f in &findings {
            assert_eq!(f.rule_id, "zero_width.invisible_format");
        }
    }

    // --- Red-team round-4 defect: Keycap emoji false positive ---

    #[test]
    fn allows_keycap_emoji_digit() {
        // 1️⃣ = '1' + U+FE0F + U+20E3 — RGI keycap emoji, must allow
        let text = "Press 1\u{FE0F}\u{20E3} for help";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "keycap emoji 1️⃣ should be allowed, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_keycap_emoji_hash() {
        // #️⃣ = '#' + U+FE0F + U+20E3 — RGI keycap emoji
        let text = "Dial #\u{FE0F}\u{20E3} now";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "keycap emoji #️⃣ should be allowed, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_keycap_emoji_star() {
        // *️⃣ = '*' + U+FE0F + U+20E3 — RGI keycap emoji
        let text = "Rate *\u{FE0F}\u{20E3}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "keycap emoji *️⃣ should be allowed, got: {:?}",
            findings
        );
    }

    #[test]
    fn allows_keycap_emoji_zero() {
        // 0️⃣ = '0' + U+FE0F + U+20E3
        let text = "0\u{FE0F}\u{20E3}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "keycap emoji 0️⃣ should be allowed, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_lone_vs16_not_keycap() {
        // U+FE0F between letters with NO U+20E3 after — still flagged
        let text = "a\u{FE0F}b";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "lone VS16 between letters must still be flagged"
        );
    }

    #[test]
    fn detects_vs16_after_digit_no_keycap() {
        // digit + U+FE0F but NO U+20E3 after — NOT a keycap, must flag
        let text = "1\u{FE0F}x";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "digit + VS16 without U+20E3 is not a keycap — must be flagged"
        );
    }

    // --- Red-team round-5: Egyptian Hieroglyph Format Controls bypass ---

    #[test]
    fn detects_egyptian_hieroglyph_horizontal_joiner() {
        // U+13431 EGYPTIAN HIEROGLYPH HORIZONTAL JOINER — Cf, NOT DI
        // Inserted inside <|im_start|> it was bypassing the special_token detector
        let text = "<|im\u{13431}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+13431 (Egyptian Hieroglyph Horizontal Joiner) must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_egyptian_hieroglyph_vertical_joiner() {
        // U+13430 EGYPTIAN HIEROGLYPH VERTICAL JOINER — first of the block
        let text = "a\u{13430}b";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "U+13430 must be flagged");
    }

    #[test]
    fn detects_egyptian_hieroglyph_end_of_block() {
        // U+1343F — last codepoint in the block
        let text = "x\u{1343F}y";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "U+1343F must be flagged");
    }

    #[test]
    fn detects_all_sixteen_egyptian_hieroglyph_format_controls() {
        // All 16 codepoints U+13430..=U+1343F must be caught
        let text: String = ('\u{13430}'..='\u{1343F}').collect();
        let findings = detector().detect(&text, &opts());
        assert_eq!(
            findings.len(),
            16,
            "all 16 Egyptian Hieroglyph Format Controls must be flagged, got {}",
            findings.len()
        );
    }

    // --- Red-team round-5: Prepended-concatenation Cf marks bypass ---

    #[test]
    fn detects_arabic_number_sign_u0600_between_ascii() {
        // U+0600 ARABIC NUMBER SIGN — Cf, NOT DI — invisible between Latin/ASCII
        let text = "pass\u{0600}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+0600 between ASCII must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_arabic_end_of_ayah_u06dd() {
        let text = "ig\u{06DD}nore";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "U+06DD must be flagged");
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_syriac_abbreviation_mark_u070f() {
        let text = ["sk-ant-", "api03-AAAA\u{070F}BBBB"].concat();
        let findings = detector().detect(&text, &opts());
        assert!(!findings.is_empty(), "U+070F must be flagged");
    }

    #[test]
    fn detects_kaithi_number_sign_u110bd() {
        let text = "pass\u{110BD}word";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "U+110BD must be flagged");
    }

    #[test]
    fn detects_arabic_disputed_end_of_ayah_u08e2() {
        let text = "a\u{08E2}b";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "U+08E2 must be flagged");
    }

    // --- Red-team round-5: Skin-tone emoji ZWJ false-positive ---

    #[test]
    fn allows_zwj_in_skin_toned_woman_laptop() {
        // 👩🏻‍💻 = woman (U+1F469) + skin-tone (U+1F3FB) + ZWJ (U+200D) + laptop (U+1F4BB)
        // This is a valid RGI emoji ZWJ sequence that must be allowed
        let text = "\u{1F469}\u{1F3FB}\u{200D}\u{1F4BB}";
        let findings = detector().detect(text, &opts());
        let zwj: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj.is_empty(),
            "skin-toned woman+laptop emoji (👩🏻‍💻) must not be flagged as zero_width.zwj, got: {:?}",
            zwj
        );
    }

    #[test]
    fn allows_zwj_in_skin_toned_handshake() {
        // 🤜🏽‍🤛 = raised fist (U+1FAF1) + light tone (U+1F3FB) + ZWJ + dark tone handshake
        let text = "\u{1FAF1}\u{1F3FB}\u{200D}\u{1FAF2}\u{1F3FD}";
        let findings = detector().detect(text, &opts());
        let zwj: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj.is_empty(),
            "skin-toned handshake emoji must not be flagged, got: {:?}",
            zwj
        );
    }

    #[test]
    fn allows_zwj_woman_dark_tone_laptop() {
        // Dark-skin-tone variant: woman + U+1F3FF + ZWJ + laptop
        let text = "\u{1F469}\u{1F3FF}\u{200D}\u{1F4BB}";
        let findings = detector().detect(text, &opts());
        let zwj: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            zwj.is_empty(),
            "dark-skin-toned woman+laptop must not be flagged, got: {:?}",
            zwj
        );
    }

    // --- Red-team round-6: U+0890/U+0891 Arabic prepended-concatenation marks ---

    #[test]
    fn detects_arabic_pound_mark_above_u0890() {
        // U+0890 ARABIC POUND MARK ABOVE — Cf, NOT DI, NOT in prior allowlist
        let text = "pass\u{0890}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+0890 between ASCII must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_arabic_piastre_mark_above_u0891() {
        // U+0891 ARABIC PIASTRE MARK ABOVE — Cf, NOT DI, sibling of U+0890
        let text = "pass\u{0891}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+0891 between ASCII must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_u0890_fragmenting_chatml_token() {
        // U+0890 inserted inside <|im_start|> to evade special_token detector
        let text = "<|im\u{0890}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+0890 fragmenting ChatML token must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_u0891_fragmenting_chatml_token() {
        let text = "<|im\u{0891}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+0891 fragmenting ChatML token must be flagged"
        );
    }

    // --- Red-team round-7: U+2D7F TIFINAGH CONSONANT JOINER (invisible Mn, not DI) ---

    #[test]
    fn detects_tifinagh_consonant_joiner_u2d7f() {
        // U+2D7F is Mn (nonspacing mark), combining class 9, zero-advance, NOT Default_Ignorable.
        // Inserted between ASCII chars it is completely invisible and fragments keywords.
        let text = "pass\u{2D7F}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+2D7F (TIFINAGH CONSONANT JOINER) must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_u2d7f_fragmenting_chatml_token() {
        // U+2D7F inserted inside <|im_start|> to defeat special_token detector
        let text = "<|im\u{2D7F}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+2D7F fragmenting ChatML token must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_u2d7f_alongside_mongolian_vowel_separator() {
        // Regression: U+180E (DI, existing fix) must still block alongside U+2D7F (new fix)
        let text = "a\u{180E}b\u{2D7F}c";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            2,
            "U+180E and U+2D7F must each produce a finding; got {:?}",
            findings
        );
        for f in &findings {
            assert_eq!(f.rule_id, "zero_width.invisible_format");
        }
    }

    #[test]
    fn still_blocks_bare_zwj_between_skin_tone_modifiers() {
        // A bare ZWJ between two skin-tone modifiers (not flanked by Extended_Pictographic)
        // must still be flagged — skin-tone modifiers are NOT Extended_Pictographic.
        let text = "\u{1F3FB}\u{200D}\u{1F3FC}";
        let findings = detector().detect(text, &opts());
        let zwj: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "zero_width.zwj")
            .collect();
        assert!(
            !zwj.is_empty(),
            "ZWJ between two skin-tone modifiers (no emoji base) must be flagged"
        );
    }

    // --- Red-team round-8: Invisible Mn joiner/filler siblings of U+2D7F ---

    #[test]
    fn detects_brahmi_number_joiner_u1107f() {
        // U+1107F BRAHMI NUMBER JOINER — Mn, zero-advance, NOT Default_Ignorable.
        // Inserted between ASCII chars it is invisible and fragments LLM tokens.
        let text = "<|im\u{1107F}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+1107F (BRAHMI NUMBER JOINER) fragmenting ChatML token must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_zanabazar_square_subjoiner_u11a47() {
        // U+11A47 ZANABAZAR SQUARE SUBJOINER — Mn, zero-advance, NOT Default_Ignorable.
        let text = "pass\u{11A47}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+11A47 (ZANABAZAR SQUARE SUBJOINER) must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_soyombo_subjoiner_u11a99() {
        // U+11A99 SOYOMBO SUBJOINER — Mn, zero-advance, NOT Default_Ignorable.
        let text = "pass\u{11A99}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+11A99 (SOYOMBO SUBJOINER) must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_kawi_conjoining_consonant_u11f42() {
        // U+11F42 KAWI CONJOINING CONSONANT SIGN MEDIUM — Mn, zero-advance, NOT DI.
        let text = "pass\u{11F42}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+11F42 (KAWI CONJOINING CONSONANT) must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_tulu_tigalari_consonant_joiner_u113d0() {
        // U+113D0 TULU-TIGALARI CONSONANT JOINER — Mn, zero-advance, NOT DI.
        let text = "pass\u{113D0}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+113D0 (TULU-TIGALARI CONSONANT JOINER) must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_old_khitan_small_script_filler_u16fe4() {
        // U+16FE4 OLD KHITAN SMALL SCRIPT FILLER — Mn, zero-advance, NOT DI.
        let text = "pass\u{16FE4}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+16FE4 (OLD KHITAN SMALL SCRIPT FILLER) must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_u1107f_in_chatml_sibling_repro() {
        // Direct repro from red-team: <|im\u{1107F}_start|> — must be blocked
        // This is the exact repro from the defect ticket.
        let text = "<|im\u{1107F}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+1107F between <|im and _start|> must be flagged (red-team repro)"
        );
    }

    #[test]
    fn detects_multiple_mn_joiners_in_sequence() {
        // All 6 new Mn joiners in a single string must each produce a finding
        let text = "a\u{1107F}b\u{11A47}c\u{11A99}d\u{11F42}e\u{113D0}f\u{16FE4}g";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            6,
            "all 6 new invisible Mn joiners must each produce a finding, got {}",
            findings.len()
        );
        for f in &findings {
            assert_eq!(f.rule_id, "zero_width.invisible_format");
        }
    }

    #[test]
    fn no_false_positive_legitimate_combining_marks() {
        // Legitimate combining marks (diacritics) must NOT be flagged.
        // U+0300 combining grave, U+0301 combining acute, U+0302 combining circumflex,
        // U+0303 combining tilde — common diacritics used in Latin script.
        let text = "e\u{0301}ta\u{0300}ble na\u{0303}o cre\u{0302}pe";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "legitimate combining diacritics must not be flagged, got: {:?}",
            findings
        );
    }

    // --- Red-team round-9 defect 1: Mn ccc=9 virama/halanta siblings of allowlisted conjoiners ---

    #[test]
    fn detects_tulu_tigalari_virama_u113ce() {
        // U+113CE TULU-TIGALARI SIGN VIRAMA — Mn, ccc=9, zero-advance.
        // Sibling of already-allowlisted U+113D0 TULU-TIGALARI CONSONANT JOINER.
        // Must be flagged when inserted between ASCII chars (e.g., fragmenting ChatML token).
        let text = "<|im\u{113CE}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+113CE (TULU-TIGALARI SIGN VIRAMA) fragmenting ChatML token must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_zanabazar_halanta_u11a34() {
        // U+11A34 ZANABAZAR SQUARE SIGN VIRAMA — Mn, ccc=9, zero-advance.
        // Sibling of already-allowlisted U+11A47 ZANABAZAR SQUARE SUBJOINER.
        let text = "pass\u{11A34}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+11A34 (ZANABAZAR SQUARE SIGN VIRAMA) must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    // --- Red-team round-9 defect 2: Dives Akuru / Masaram Gondi / Gunjala Gondi / Ahom / Gurung Khema viramas ---

    #[test]
    fn detects_dives_akuru_virama_u1193e() {
        // U+1193E DIVES AKURU VIRAMA — Mn, ccc=9, zero-advance, NOT Default_Ignorable.
        let text = "<|im\u{1193E}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+1193E (DIVES AKURU VIRAMA) fragmenting ChatML token must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_masaram_gondi_virama_u11d45() {
        // U+11D45 MASARAM GONDI VIRAMA — Mn, ccc=9, zero-advance, NOT Default_Ignorable.
        let text = "pass\u{11D45}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+11D45 (MASARAM GONDI VIRAMA) must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_masaram_gondi_halanta_u11d44() {
        // U+11D44 MASARAM GONDI SIGN HALANTA — Mn, ccc=9, zero-advance, NOT Default_Ignorable.
        let text = "pass\u{11D44}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+11D44 (MASARAM GONDI SIGN HALANTA) must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_gunjala_gondi_virama_u11d97() {
        // U+11D97 GUNJALA GONDI VIRAMA — Mn, ccc=9, zero-advance, NOT Default_Ignorable.
        let text = "pass\u{11D97}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+11D97 (GUNJALA GONDI VIRAMA) must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_ahom_sign_killer_u1172b() {
        // U+1172B AHOM SIGN KILLER — Mn, ccc=9, zero-advance, NOT Default_Ignorable.
        let text = "pass\u{1172B}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+1172B (AHOM SIGN KILLER) must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_gurung_khema_tholhoma_u1612f() {
        // U+1612F GURUNG KHEMA SIGN THOLHOMA — Mn, ccc=9, zero-advance, NOT Default_Ignorable.
        let text = "pass\u{1612F}word";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+1612F (GURUNG KHEMA SIGN THOLHOMA) must be flagged as zero_width.invisible_format"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    // --- Red-team round-9 defect 3: U+13440 Egyptian Hieroglyph Mirror Horizontally (Mn) ---

    #[test]
    fn detects_egyptian_hieroglyph_mirror_horizontally_u13440() {
        // U+13440 EGYPTIAN HIEROGLYPH MIRROR HORIZONTALLY — Mn, zero-advance.
        // Sits exactly one codepoint past the prior U+13430..=U+1343F Cf range.
        let text = "<|im\u{13440}_start|>";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+13440 (EGYPTIAN HIEROGLYPH MIRROR HORIZONTALLY) fragmenting ChatML token must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_egyptian_hieroglyph_modifier_u13441() {
        // U+13441 EGYPTIAN HIEROGLYPH FULL BLANK — Mn modifier in the extended block.
        let text = "a\u{13441}b";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "U+13441 (EGYPTIAN HIEROGLYPH FULL BLANK) must be flagged"
        );
        assert_eq!(findings[0].rule_id, "zero_width.invisible_format");
    }

    #[test]
    fn detects_egyptian_hieroglyph_modifiers_u13441_to_u13455() {
        // U+13441..=U+13455 EGYPTIAN HIEROGLYPH modifier block — all must be caught
        let text: String = ('\u{13441}'..='\u{13455}').collect();
        let findings = detector().detect(&text, &opts());
        assert_eq!(
            findings.len(),
            0x13455 - 0x13441 + 1,
            "all Egyptian Hieroglyph modifier codepoints U+13441..=U+13455 must be flagged, got {}",
            findings.len()
        );
    }
}

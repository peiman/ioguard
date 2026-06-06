use std::collections::HashSet;

use icu_properties::{props::Script, CodePointMapData};
use unicode_normalization::UnicodeNormalization;

use crate::types::{Category, Direction, Finding, ScanOptions, Severity};
use unicode_security::confusable_detection::skeleton;

/// Curated wordlist of high-value brand/security targets for whole-script spoof detection.
/// A single-script non-Latin token whose full UTS#39 skeleton case-insensitively matches
/// one of these words is blocked as a whole-script spoof. Maintained by design.
const HIGH_VALUE_TARGETS: &[&str] = &[
    "account",
    "amazon",
    "apple",
    "bank",
    "google",
    "login",
    "microsoft",
    "netflix",
    "password",
    "paypal",
    "secure",
    "signin",
    "token",
    "verify",
];

/// Detector for mixed-script confusable sequences (UTS#39 homoglyph attacks).
///
/// ## Algorithm (per whitespace-delimited token)
///
/// Non-alphabetic characters — emoji, symbols, punctuation, combining marks, digits —
/// are ignored when determining scripts and confusable counts.
///
/// **Gate 1 — Pure ASCII**: if the entire text is ASCII, return immediately.
///
/// **Gate 2 — No non-ASCII letter**: if the token contains no non-ASCII alphabetic
/// character, skip it.
///
/// **Classification**: for each alphabetic character, look up its Unicode Script
/// property (via `icu_properties`) and determine whether it is a *cross-script
/// Latin-confusable*: a non-ASCII char whose per-character UTS#39 skeleton is
/// entirely ASCII alphabetic (e.g. Cyrillic а→a, math-bold 𝐩→p, fullwidth ｇ→g).
///
/// **Rule 3 — Single-script** (all alphabetic chars share one script):
/// - *Latin*: if `cross_script_confusables > 0`, compute the full-token UTS#39
///   skeleton, extract ASCII-alpha only, and check against `HIGH_VALUE_TARGETS` —
///   **BLOCK** if matched (catches fullwidth laundering); otherwise **ALLOW**.
///   If `cross_script_confusables == 0`, **ALLOW** (normal accented Latin: café, résumé).
/// - *Non-Latin* (Cyrillic, Greek, Han, Common, …): compute the full-token skeleton;
///   if it is entirely ASCII, extract alpha-only and check against `HIGH_VALUE_TARGETS`
///   — **BLOCK** if matched (catches whole-script spoofs: math-bold paypal, etc.);
///   otherwise **ALLOW** (legitimate: спасибо, αβγ, 你好世界, κόσμος).
///
/// **Rule 4 — Mixed-script** (≥ 2 scripts among alphabetic chars):
/// - If `cross_script_confusables >= 1` AND `matches_high_value_target` → **BLOCK**
///   (at least one char is a Latin-lookalike imposter spoofing a known brand/keyword;
///   poison chars like Greek β or emoji cannot flip this).
/// - Otherwise → **ALLOW** (β-test, Δx: Greek letter with non-ASCII skeleton + Latin;
///   α-particle, γ-ray, σ-bond: Greek letter with ASCII skeleton but not a target word).
///
/// ## Zero false positives on
/// - Pure ASCII text
/// - CJK-only (skeleton retains non-ASCII chars)
/// - Accented Latin: café, résumé, naïve (single Latin script, skeleton not a target)
/// - Single-script Cyrillic: спасибо (skeleton not entirely ASCII, or not a target word)
/// - Single-script Greek: αβγ, ορος, κόσμος (skeleton not in target wordlist)
/// - Math symbols ∞ ∑ ∏ √ (no alphabetic chars)
/// - Emoji sequences (not alphabetic → ignored)
/// - Greek math notation β-test, Δx, Δx🎉 (β→ß non-ASCII; Δ non-ASCII → 0 confusables)
/// - Greek scientific notation α-particle, γ-ray, σ-bond, ρ-meson, ν-beam
///   (ASCII-folding Greek prefix + non-target Latin word → 0 confusables OR not a target)
///
/// ## Catches
/// - Mathematical Bold/Italic (U+1D400-U+1D7FF): every char a confusable, skeleton is
///   an ASCII target word — BLOCK
/// - Fullwidth Latin (U+FF21-U+FF5A): Latin script, confusables > 0, skeleton is target
/// - Cyrillic lookalikes in Latin words (pаypal: Cyrillic а→a): mixed-script, conf ≥ 1
/// - Poison-char bypass attempts (β, emoji suffix): ignored for confusable count;
///   Cyrillic confusable alone is sufficient to trigger the mixed-script block
pub struct HomoglyphDetector;

impl HomoglyphDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect mixed-script confusable sequences in the given text.
    pub fn detect(&self, text: &str, _opts: &ScanOptions) -> Vec<Finding> {
        // Gate 1: pure ASCII cannot have cross-script confusables.
        if text.is_ascii() {
            return vec![];
        }

        let script_map = CodePointMapData::<Script>::new();
        let mut findings = Vec::new();

        for (word_start, word_end, word) in words_with_positions(text) {
            // Skip pure-ASCII tokens (no non-ASCII means no cross-script risk).
            if word.is_ascii() {
                continue;
            }

            // Gate 2: skip tokens with no non-ASCII letter-like character.
            // Pure math/symbol tokens like "∞" or "€" have no letter imposters.
            // We broaden the check to also admit non-ASCII chars whose NFKC fold
            // contains ASCII letters — this catches parenthesized Latin (U+2474-U+24B5,
            // category So) which are not considered alphabetic by Rust's is_alphabetic()
            // but NFKC-decompose to "(letter)" sequences.
            let has_non_ascii_letter = word.chars().any(|c| !c.is_ascii() && c.is_alphabetic());
            let has_non_ascii_nfkc_letter = if !has_non_ascii_letter {
                // Only compute this when the cheaper check failed.
                word.chars().any(|c| {
                    if c.is_ascii() {
                        return false;
                    }
                    let nfkc: String = c.to_string().nfkc().collect();
                    nfkc.chars().any(|k| k.is_ascii_alphabetic())
                })
            } else {
                false
            };
            if !has_non_ascii_letter && !has_non_ascii_nfkc_letter {
                continue;
            }

            // Classify each alphabetic character by script and confusability.
            // Non-alphabetic chars (emoji, digits, symbols, punctuation) are ignored.
            let mut scripts: HashSet<Script> = HashSet::new();
            let mut cross_script_confusables: usize = 0;

            for c in word.chars() {
                if !c.is_alphabetic() {
                    continue;
                }
                let script = script_map.get(c);
                scripts.insert(script);

                // A cross-script Latin-confusable is a non-ASCII char whose
                // per-character skeleton is entirely ASCII alphabetic,
                // OR a Latin small-cap/IPA-modifier letter that maps to ASCII.
                // The second case is needed because skeleton() does NOT decompose
                // small-cap letters (e.g. ᴘ → "ᴘ", not "p"), so they would
                // otherwise fall through the gate with confusables==0.
                if !c.is_ascii() {
                    let per_skel: String = skeleton(&c.to_string()).collect();
                    let skel_folds_to_ascii =
                        !per_skel.is_empty() && per_skel.chars().all(|s| s.is_ascii_alphabetic());
                    if skel_folds_to_ascii || is_small_cap_or_ipa_modifier(c) {
                        cross_script_confusables += 1;
                    }
                }
            }

            // Special case: tokens whose chars are non-alphabetic symbols but whose
            // NFKC decomposition yields ASCII letters (e.g. parenthesized Latin
            // U+2474-U+24B5: ⒫⒜⒴⒫⒜⒧ → "(p)(a)(y)(p)(a)(l)").
            // No alphabetic chars were found during classification, so `scripts` is empty.
            // Detect these by checking the NFKC alpha-fold against high-value targets.
            if scripts.is_empty() {
                let nfkc_alpha: String = word
                    .nfkc()
                    .flat_map(|c| c.to_lowercase())
                    .filter(|c| c.is_ascii_alphabetic())
                    .collect();
                if !nfkc_alpha.is_empty() && HIGH_VALUE_TARGETS.contains(&nfkc_alpha.as_str()) {
                    findings.push(Finding {
                        rule_id: "homoglyph.mixed_script_confusable".to_string(),
                        category: Category::Homoglyph,
                        severity: Severity::Block,
                        direction: Direction::Both,
                        span: (word_start, word_end),
                        preview: make_word_preview(word),
                    });
                }
                continue;
            }

            let should_block = if scripts.len() == 1 {
                // Single-script path.
                let script = *scripts.iter().next().expect("set is non-empty");
                if script == Script::Latin {
                    // Rule 3a: single-script Latin.
                    // cross_script_confusables > 0 means fullwidth or similar laundering;
                    // check the full-token skeleton against the high-value wordlist.
                    //
                    // Additionally, even when cross_script_confusables == 0, block when the
                    // NFKC fold of the full token is entirely ASCII and matches a high-value
                    // target. This catches modifier-letter superscripts (U+1D2C-U+1D6A,
                    // U+02B0-U+02B8) whose per-char skeleton stays non-ASCII (so they never
                    // increment cross_script_confusables) but NFKC-decompose to ASCII letters.
                    // Examples: ᵍᵒᵒᵍˡᵉ (U+1D4D etc.) → "google", ᵃpple → "apple".
                    let nfkc_str: String = word.nfkc().collect();
                    let nfkc_all_ascii = !nfkc_str.is_empty() && nfkc_str.is_ascii();
                    (cross_script_confusables > 0 || nfkc_all_ascii)
                        && matches_high_value_target(word)
                } else {
                    // Rule 3b: single non-Latin script (Cyrillic, Greek, Han, Common, …).
                    // Block when the full-token skeleton OR NFKC fold is entirely ASCII AND
                    // matches the high-value wordlist (catches whole-script spoofs: math-bold,
                    // fullwidth-Latin classified as non-Latin by icu_properties).
                    let token_skel: String = skeleton(word).collect();
                    let skel_all_ascii = !token_skel.is_empty() && token_skel.is_ascii();
                    let nfkc_str: String = word.nfkc().collect();
                    let nfkc_all_ascii = !nfkc_str.is_empty() && nfkc_str.is_ascii();
                    (skel_all_ascii || nfkc_all_ascii) && matches_high_value_target(word)
                }
            } else {
                // Rule 4: mixed-script path (≥ 2 scripts).
                // Block when any cross-script Latin-confusable is present AND the token
                // matches a high-value target word via targeted confusable substitution.
                //
                // NOTE: We do NOT use `matches_high_value_target(word)` (which runs the full
                // UTS#39 skeleton on the whole token) because the skeleton function maps some
                // ASCII chars to multi-char sequences (e.g. 'm' → "rn"), corrupting the
                // comparison for tokens like "miсrosoft" whose skeleton becomes "rnicrosoft".
                // Instead, `matches_high_value_target_for_rule4` only substitutes NON-ASCII
                // cross-script confusables and keeps ASCII chars as-is, then checks each
                // alphabetic segment against the target wordlist.
                //
                // This prevents false positives on Greek scientific/math notation such as
                // α-particle, γ-ray, σ-bond, ρ-meson, ν-beam — a single ASCII-folding Greek
                // letter on a non-target Latin word. Poison chars (Greek β→ß, emoji) contribute
                // 0 confusables, so they cannot suppress a Cyrillic confusable.
                cross_script_confusables >= 1 && matches_high_value_target_for_rule4(word)
            };

            if should_block {
                findings.push(Finding {
                    rule_id: "homoglyph.mixed_script_confusable".to_string(),
                    category: Category::Homoglyph,
                    severity: Severity::Block,
                    direction: Direction::Both,
                    span: (word_start, word_end),
                    preview: make_word_preview(word),
                });
            }
        }

        findings
    }
}

impl Default for HomoglyphDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether `word` matches a `HIGH_VALUE_TARGETS` entry via three independent
/// fold paths:
///
/// 1. **UTS#39 skeleton** — catches Cyrillic/math-bold spoofs reliably.
/// 2. **NFKC normalization** — reliably folds all fullwidth U+FF41–FF5A and math
///    compatibility forms to ASCII (where skeleton() may miss some letters).
/// 3. **Small-cap/IPA-modifier fold** — catches Latin small-cap (U+1D00–U+1D7F)
///    and IPA-modifier letters that NFKC and skeleton() both leave non-ASCII.
///
/// BLOCK if any fold, after lowercasing and keeping only ASCII alpha chars,
/// matches a target word. Non-target words (e.g. "hello", "café") will not match.
fn matches_high_value_target(word: &str) -> bool {
    // Path 1: UTS#39 skeleton fold
    let via_skeleton: String = skeleton(word)
        .flat_map(|c| c.to_lowercase())
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    if HIGH_VALUE_TARGETS.contains(&via_skeleton.as_str()) {
        return true;
    }

    // Path 2: NFKC normalization fold (reliably folds fullwidth U+FF21-FF5A
    // and math compatibility forms to ASCII)
    let via_nfkc: String = word
        .nfkc()
        .flat_map(|c| c.to_lowercase())
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    if HIGH_VALUE_TARGETS.contains(&via_nfkc.as_str()) {
        return true;
    }

    // Path 3: Small-cap/IPA-modifier fold.
    // Latin small-capital letters (U+1D00 ᴀ, U+1D18 ᴘ, etc.) and IPA-modifier
    // letters (U+028F ʏ, U+029F ʟ, etc.) are not decomposed by NFKC or skeleton(),
    // so a direct mapping table is needed to catch e.g. ᴘᴀʏᴘᴀʟ → paypal.
    let via_small_cap: String = word
        .chars()
        .map(fold_small_cap_ipa)
        .flat_map(|c| c.to_lowercase())
        .filter(|c| c.is_ascii_alphabetic())
        .collect();
    if HIGH_VALUE_TARGETS.contains(&via_small_cap.as_str()) {
        return true;
    }

    // Path 4: Explicit fold table (priority) + per-char skeleton fallback.
    // Handles mixed cases like whole-script Cyrillic tokens containing Cyrillic
    // palochka (U+04CF/U+04C0): most chars fold via skeleton (e.g. р→p, а→a),
    // but palochka has an INCORRECT UTS#39 skeleton mapping (ӏ→'i'), whereas
    // visually it looks like 'l'. The explicit fold table takes precedence over
    // skeleton for chars it covers, ensuring palochka maps to 'l' not 'i'.
    let via_combined: String = word
        .chars()
        .flat_map(|c| -> Vec<char> {
            if c.is_ascii_alphabetic() {
                return vec![c.to_ascii_lowercase()];
            }
            // Explicit fold table takes priority (covers palochka and small-caps).
            let explicit = fold_small_cap_ipa(c);
            if explicit != c {
                return vec![explicit.to_ascii_lowercase()];
            }
            // Fall back to per-char skeleton for other non-ASCII confusables.
            let per_skel: String = skeleton(&c.to_string())
                .flat_map(|s| s.to_lowercase())
                .collect();
            if !per_skel.is_empty() && per_skel.chars().all(|s| s.is_ascii_alphabetic()) {
                per_skel.chars().collect()
            } else {
                vec![] // no ASCII fold available → drop
            }
        })
        .collect();
    HIGH_VALUE_TARGETS.contains(&via_combined.as_str())
}

/// Rule-4-specific target check: substitute only NON-ASCII cross-script confusables
/// while keeping ASCII letters as-is (to avoid the full `skeleton()` distortion where
/// e.g. 'm' → "rn"), then check each alphabetic segment against `HIGH_VALUE_TARGETS`.
///
/// Splitting on non-alphabetic chars handles tokens like "pаypal.com" (the "pаypal"
/// segment matches "paypal") and "аmazon🎁" (the "аmazon" segment matches "amazon").
/// This gives accurate target detection without the full UTS#39 skeleton's side-effects.
///
/// IMPORTANT: A segment only triggers a block if it ITSELF contains at least one
/// non-ASCII cross-script confusable substitution. This prevents false positives on
/// tokens like "α-account" where the confusable (α) lives in a separate segment from
/// the target word ("account"). The "account" segment is pure ASCII and must not be
/// counted as a spoof — only segments that mix confusable imposters with ASCII chars
/// are actual spoofs.
fn matches_high_value_target_for_rule4(word: &str) -> bool {
    for segment in word.split(|c: char| !c.is_alphabetic()) {
        if segment.is_empty() {
            continue;
        }
        // Substitute non-ASCII confusables; keep ASCII letters as-is; drop the rest.
        // Also track whether this segment itself contains any non-ASCII confusable,
        // and whether any non-ASCII char was dropped (no ASCII fold available).
        let mut segment_has_confusable = false;
        let mut segment_has_unfolded_non_ascii = false;
        let substituted: String = segment
            .chars()
            .flat_map(|c| -> Vec<char> {
                if c.is_ascii_alphabetic() {
                    vec![c.to_ascii_lowercase()]
                } else {
                    // Non-ASCII: use per-char skeleton if it folds entirely to ASCII alpha,
                    // or small-cap/IPA fold table for Latin small-caps that skeleton() misses.
                    let per_skel: String = skeleton(&c.to_string())
                        .flat_map(|s| s.to_lowercase())
                        .collect();
                    if !per_skel.is_empty() && per_skel.chars().all(|s| s.is_ascii_alphabetic()) {
                        segment_has_confusable = true;
                        per_skel.chars().collect()
                    } else if is_small_cap_or_ipa_modifier(c) {
                        segment_has_confusable = true;
                        vec![fold_small_cap_ipa(c).to_ascii_lowercase()]
                    } else {
                        // This non-ASCII char has no ASCII fold and is dropped.
                        // Track it so we can fail closed when mixed with a confusable.
                        segment_has_unfolded_non_ascii = true;
                        vec![] // non-ASCII skeleton (e.g. β→ß, Δ→Δ) or non-confusable → drop
                    }
                }
            })
            .collect();
        // Only count this segment as a spoof if it contains at least one non-ASCII
        // confusable substitution. A bare ASCII target word in a separate segment
        // (e.g. "account" after splitting "α-account" on '-') is NOT a spoof.
        if segment_has_confusable && HIGH_VALUE_TARGETS.contains(&substituted.as_str()) {
            return true;
        }
        // Fail-closed: if a segment has at least one ASCII-folding confusable substitution
        // AND also contains a non-ASCII char that couldn't be folded (and was silently
        // dropped), the shortened substituted string may miss a HIGH_VALUE_TARGET match
        // due to the missing character. In this case, treat the segment as suspicious
        // and block. A mixed-script token where some chars fold (impostors) and some
        // don't (yet are also non-ASCII) is a strong indicator of a targeted spoof.
        // Example: bаnк → 'b' 'а'(→'a') 'n' 'к'(dropped) → "ban" misses "bank";
        // but the presence of folding Cyrillic а + non-folding Cyrillic к in a
        // mixed-script word is sufficient cause to block.
        if segment_has_confusable && segment_has_unfolded_non_ascii {
            return true;
        }
    }
    false
}

/// Map a Latin small-capital, IPA-modifier, or visually confusable letter to its
/// ASCII lowercase equivalent. Characters not in the table are returned unchanged.
///
/// Coverage: common small-cap/IPA-modifier letters used in phishing/brand spoofs,
/// plus Cyrillic palochka (U+04CF/U+04C0) which looks identical to ASCII 'l' and is
/// NOT decomposed by NFKC or UTS#39 skeleton.
#[allow(clippy::match_same_arms)]
fn fold_small_cap_ipa(c: char) -> char {
    match c {
        '\u{1D00}' => 'a', // ᴀ LATIN LETTER SMALL CAPITAL A
        '\u{0299}' => 'b', // ʙ LATIN LETTER SMALL CAPITAL B
        '\u{1D04}' => 'c', // ᴄ LATIN LETTER SMALL CAPITAL C
        '\u{1D05}' => 'd', // ᴅ LATIN LETTER SMALL CAPITAL D
        '\u{1D07}' => 'e', // ᴇ LATIN LETTER SMALL CAPITAL E
        '\u{A730}' => 'f', // ꜰ LATIN LETTER SMALL CAPITAL F
        '\u{0262}' => 'g', // ɢ LATIN LETTER SMALL CAPITAL G
        '\u{029C}' => 'h', // ʜ LATIN LETTER SMALL CAPITAL H
        '\u{026A}' => 'i', // ɪ LATIN LETTER SMALL CAPITAL I
        '\u{1D0A}' => 'j', // ᴊ LATIN LETTER SMALL CAPITAL J
        '\u{1D0B}' => 'k', // ᴋ LATIN LETTER SMALL CAPITAL K
        '\u{029F}' => 'l', // ʟ LATIN LETTER SMALL CAPITAL L
        '\u{04CF}' => 'l', // ӏ CYRILLIC SMALL LETTER PALOCHKA (visually identical to 'l')
        '\u{04C0}' => 'l', // Ӏ CYRILLIC LETTER PALOCHKA (uppercase; visually identical to 'I'/'l')
        '\u{1D0D}' => 'm', // ᴍ LATIN LETTER SMALL CAPITAL M
        '\u{0274}' => 'n', // ɴ LATIN LETTER SMALL CAPITAL N
        '\u{1D0F}' => 'o', // ᴏ LATIN LETTER SMALL CAPITAL O
        '\u{1D18}' => 'p', // ᴘ LATIN LETTER SMALL CAPITAL P
        '\u{0280}' => 'r', // ʀ LATIN LETTER SMALL CAPITAL R
        '\u{A731}' => 's', // ꜱ LATIN LETTER SMALL CAPITAL S
        '\u{1D1B}' => 't', // ᴛ LATIN LETTER SMALL CAPITAL T
        '\u{1D1C}' => 'u', // ᴜ LATIN LETTER SMALL CAPITAL U
        '\u{1D20}' => 'v', // ᴠ LATIN LETTER SMALL CAPITAL V
        '\u{1D21}' => 'w', // ᴡ LATIN LETTER SMALL CAPITAL W
        '\u{028F}' => 'y', // ʏ LATIN LETTER SMALL CAPITAL Y
        '\u{1D22}' => 'z', // ᴢ LATIN LETTER SMALL CAPITAL Z
        _ => c,
    }
}

/// Returns `true` if the character is a Latin small-capital or IPA-modifier
/// letter that maps to an ASCII letter via `fold_small_cap_ipa`.
/// Used to count small-cap chars as cross-script confusables so that Rule 3a
/// (single-script Latin) triggers `matches_high_value_target`.
fn is_small_cap_or_ipa_modifier(c: char) -> bool {
    fold_small_cap_ipa(c) != c
}

/// Iterate over whitespace-delimited tokens in `text`, yielding
/// `(byte_start, byte_end, token_str)` for each token.
fn words_with_positions(text: &str) -> impl Iterator<Item = (usize, usize, &str)> {
    // Collect all tokens eagerly so we can return a simple Vec iterator.
    let mut tokens: Vec<(usize, usize, &str)> = Vec::new();
    let mut chars = text.char_indices().peekable();

    loop {
        // Skip whitespace.
        while let Some(&(_, ch)) = chars.peek() {
            if ch.is_whitespace() {
                chars.next();
            } else {
                break;
            }
        }

        // Peek at the start of the next token.
        let word_start = match chars.peek() {
            Some(&(idx, _)) => idx,
            None => break, // end of string
        };

        // Consume until whitespace or end.
        let mut word_end = word_start;
        while let Some(&(idx, ch)) = chars.peek() {
            if ch.is_whitespace() {
                break;
            }
            word_end = idx + ch.len_utf8();
            chars.next();
        }

        tokens.push((word_start, word_end, &text[word_start..word_end]));
    }

    tokens.into_iter()
}

/// Produce a safe preview of a flagged word: first 8 chars + "..."
fn make_word_preview(word: &str) -> String {
    let chars: String = word.chars().take(8).collect();
    format!("{chars}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> HomoglyphDetector {
        HomoglyphDetector::new()
    }

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    #[test]
    fn detects_cyrillic_a_in_latin_word() {
        // "pаypal" where 'а' is Cyrillic U+0430, not Latin 'a'
        let text = "p\u{0430}ypal";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            1,
            "Cyrillic 'а' in Latin word should be flagged"
        );
        assert_eq!(findings[0].rule_id, "homoglyph.mixed_script_confusable");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_cyrillic_o_in_latin() {
        // "gооgle" where 'о' chars are Cyrillic U+043E, not Latin 'o'
        let text = "g\u{043E}\u{043E}gle";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            1,
            "Cyrillic 'о' in Latin word should be flagged"
        );
        assert_eq!(findings[0].rule_id, "homoglyph.mixed_script_confusable");
    }

    #[test]
    fn no_fp_pure_ascii() {
        let text = "paypal google amazon";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "pure ASCII should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_cjk_only() {
        let text = "你好世界";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "CJK-only text should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_accented_latin() {
        let text = "café résumé naïve über";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "accented Latin should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_cyrillic_only() {
        let text = "Привет мир";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "Cyrillic-only text should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_math_symbols() {
        let text = "∑ ∏ √ ∞ π ∂ ∫ ∇ ≤ ≥ ≠ ≈";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "math symbols should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_emoji() {
        let text = "Hello 👨‍👩‍👧‍👦 World 🌍 🎉";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "emoji sequences should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_japanese_mixed() {
        // Japanese mixes Kanji (Han), Hiragana, and Katakana — single-script via UTS#39 JPAN
        let text = "日本語テスト ひらがな カタカナ";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "Japanese mixed-kana text should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_mixed_in_sentence() {
        // Sentence with one confusable word among clean words
        let text = "Please visit p\u{0430}ypal.com to verify your account.";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "mixed-script confusable in sentence should be flagged"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "homoglyph.mixed_script_confusable"),
            "expected homoglyph.mixed_script_confusable finding"
        );
    }

    #[test]
    fn span_offsets_correct() {
        // "pay " is 4 bytes, then "p\u{0430}ypal" starts at byte 4
        let text = "pay p\u{0430}ypal end";
        let findings = detector().detect(text, &opts());
        assert_eq!(findings.len(), 1, "expected 1 finding");
        let (start, end) = findings[0].span;
        // "pay " = 4 bytes, "p" = 1, Cyrillic 'а' = 2 bytes, "ypal" = 4 bytes → 7 byte word
        assert_eq!(start, 4, "word start should be at byte 4");
        assert_eq!(end, 4 + 7, "word end should cover the 7-byte word");
        assert_eq!(&text[start..end], "p\u{0430}ypal");
    }

    #[test]
    fn empty_string_no_findings() {
        let findings = detector().detect("", &opts());
        assert!(findings.is_empty());
    }

    #[test]
    fn no_fp_single_non_ascii_char() {
        // Euro sign is Common script — not a confusable
        let text = "price: 5€";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "currency symbol should produce no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_math_bold_paypal_laundering() {
        // Mathematical Bold: U+1D429 U+1D41A U+1D432 U+1D429 U+1D41A U+1D425
        // skeleton() maps these to "paypal" (ASCII) — must be caught as laundering
        let text = "\u{1D429}\u{1D41A}\u{1D432}\u{1D429}\u{1D41A}\u{1D425}";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            1,
            "math-bold 'paypal' laundering must be flagged"
        );
        assert_eq!(findings[0].rule_id, "homoglyph.mixed_script_confusable");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_fullwidth_google_laundering() {
        // Fullwidth: U+FF47 U+FF4F U+FF4F U+FF47 U+FF4C U+FF45
        // skeleton() maps these to "google" (ASCII) — must be caught as laundering
        let text = "\u{FF47}\u{FF4F}\u{FF4F}\u{FF47}\u{FF4C}\u{FF45}";
        let findings = detector().detect(text, &opts());
        assert_eq!(
            findings.len(),
            1,
            "fullwidth 'google' laundering must be flagged"
        );
        assert_eq!(findings[0].rule_id, "homoglyph.mixed_script_confusable");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn no_fp_greek_beta_test() {
        // Greek beta (U+03B2) + Latin "-test" — legitimate math notation
        let text = "\u{03B2}-test";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "Greek beta in 'β-test' must NOT be flagged, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_delta_x() {
        // Greek capital delta (U+0394) + Latin "x" — legitimate math notation
        let text = "\u{0394}x";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "Greek delta in 'Δx' must NOT be flagged, got: {:?}",
            findings
        );
    }

    // --- Poison-char bypass tests (must block) ---

    #[test]
    fn detects_cyrillic_with_greek_poison_suffix() {
        // Repro 1: Cyrillic а in "paypal" + Greek β suffix
        let text = "p\u{0430}ypal\u{03B2}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "Cyrillic+Greek poison must block");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_cyrillic_with_emoji_poison_suffix() {
        // Repro 2: Cyrillic а in "paypal" + emoji 🎉 suffix
        let text = "p\u{0430}ypal\u{1F389}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "Cyrillic+emoji poison must block");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_mathbold_with_greek_poison_suffix() {
        // Repro 3: math-bold paypal + Greek β
        let text = "\u{1D429}\u{1D41A}\u{1D432}\u{1D429}\u{1D41A}\u{1D425}\u{03B2}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "math-bold+Greek poison must block");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_emoji_suffixed_spoof_in_prose() {
        // Repro 4: "Claim reward at аmazon🎁 today"
        let text = "Claim reward at \u{0430}mazon\u{1F381} today";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "emoji-suffixed spoof in prose must block"
        );
        assert_eq!(findings[0].severity, Severity::Block);
    }

    // --- Must-allow: non-confusable with extras ---

    #[test]
    fn no_fp_greek_delta_x_with_emoji() {
        // Δx🎉 — confusable_subs==0 because Δ skeleton is non-ASCII
        let text = "\u{0394}x\u{1F389}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "Δx🎉 must NOT be flagged, got: {:?}",
            findings
        );
    }

    // --- Adversarial variants (must block) ---

    #[test]
    fn detects_greek_poison_as_prefix() {
        // Greek β prefix + Cyrillic а in paypal body
        let text = "\u{03B2}p\u{0430}ypal";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "Greek-prefix poison variant must block"
        );
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_two_poison_chars() {
        // Cyrillic а in paypal + two poison chars (β and 🎉)
        let text = "p\u{0430}ypal\u{03B2}\u{1F389}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "double-poison variant must block");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn detects_cyrillic_s_in_microsoft() {
        // "miсrosoft" with Cyrillic с (U+0441) + Greek β suffix
        let text = "mi\u{0441}rosoft\u{03B2}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "Cyrillic с in microsoft+poison must block"
        );
        assert_eq!(findings[0].severity, Severity::Block);
    }

    // --- New tests: Step 1 TDD RED phase ---

    #[test]
    fn blocks_microsoft_cyrillic_s_with_emoji() {
        // "miсrosoft🎉" — Cyrillic с (U+0441) + emoji suffix
        let text = "mi\u{0441}rosoft\u{1F389}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "Cyrillic с in microsoft+emoji must block"
        );
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn no_fp_cyrillic_spasibo() {
        // Single-script Cyrillic word — must never false-positive
        let text = "\u{0441}\u{043F}\u{0430}\u{0441}\u{0438}\u{0431}\u{043E}"; // спасибо
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "single-script Cyrillic 'спасибо' must allow, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_alpha_beta_gamma() {
        // Single-script Greek word — must never false-positive
        let text = "\u{03B1}\u{03B2}\u{03B3}"; // αβγ
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "single-script Greek 'αβγ' must allow, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_oros() {
        // Single-script Greek word with chars that have ASCII-looking skeletons
        let text = "\u{03BF}\u{03C1}\u{03BF}\u{03C2}"; // ορος
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "single-script Greek 'ορος' must allow, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_kosmos() {
        // Single-script Greek word with accent
        let text = "\u{03BA}\u{03CC}\u{03C3}\u{03BC}\u{03BF}\u{03C2}"; // κόσμος
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "single-script Greek 'κόσμος' must allow, got: {:?}",
            findings
        );
    }

    // --- Fullwidth must-block tests (TDD RED — will fail before NFKC fix) ---

    #[test]
    fn blocks_fullwidth_account() {
        // Fullwidth 'account': U+FF41 U+FF43 U+FF43 U+FF4F U+FF55 U+FF4E U+FF54
        let text = "\u{FF41}\u{FF43}\u{FF43}\u{FF4F}\u{FF55}\u{FF4E}\u{FF54}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'account' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_amazon() {
        // Fullwidth 'amazon': U+FF41 U+FF4D U+FF41 U+FF5A U+FF4F U+FF4E
        let text = "\u{FF41}\u{FF4D}\u{FF41}\u{FF5A}\u{FF4F}\u{FF4E}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'amazon' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_apple() {
        // Fullwidth 'apple': U+FF41 U+FF50 U+FF50 U+FF4C U+FF45
        let text = "\u{FF41}\u{FF50}\u{FF50}\u{FF4C}\u{FF45}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'apple' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_bank() {
        // Fullwidth 'bank': U+FF42 U+FF41 U+FF4E U+FF4B
        let text = "\u{FF42}\u{FF41}\u{FF4E}\u{FF4B}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'bank' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_login() {
        // Fullwidth 'login': U+FF4C U+FF4F U+FF47 U+FF49 U+FF4E
        let text = "\u{FF4C}\u{FF4F}\u{FF47}\u{FF49}\u{FF4E}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'login' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_microsoft() {
        // Fullwidth 'microsoft': U+FF4D U+FF49 U+FF43 U+FF52 U+FF4F U+FF53 U+FF4F U+FF46 U+FF54
        let text = "\u{FF4D}\u{FF49}\u{FF43}\u{FF52}\u{FF4F}\u{FF53}\u{FF4F}\u{FF46}\u{FF54}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "fullwidth 'microsoft' must be blocked"
        );
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_netflix() {
        // Fullwidth 'netflix': U+FF4E U+FF45 U+FF54 U+FF46 U+FF4C U+FF49 U+FF58
        let text = "\u{FF4E}\u{FF45}\u{FF54}\u{FF46}\u{FF4C}\u{FF49}\u{FF58}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'netflix' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_password() {
        // Fullwidth 'password': U+FF50 U+FF41 U+FF53 U+FF53 U+FF57 U+FF4F U+FF52 U+FF44
        let text = "\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'password' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_paypal() {
        // Fullwidth 'paypal': U+FF50 U+FF41 U+FF59 U+FF50 U+FF41 U+FF4C
        let text = "\u{FF50}\u{FF41}\u{FF59}\u{FF50}\u{FF41}\u{FF4C}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'paypal' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_secure() {
        // Fullwidth 'secure': U+FF53 U+FF45 U+FF43 U+FF55 U+FF52 U+FF45
        let text = "\u{FF53}\u{FF45}\u{FF43}\u{FF55}\u{FF52}\u{FF45}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'secure' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_signin() {
        // Fullwidth 'signin': U+FF53 U+FF49 U+FF47 U+FF4E U+FF49 U+FF4E
        let text = "\u{FF53}\u{FF49}\u{FF47}\u{FF4E}\u{FF49}\u{FF4E}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'signin' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_token() {
        // Fullwidth 'token': U+FF54 U+FF4F U+FF4B U+FF45 U+FF4E
        let text = "\u{FF54}\u{FF4F}\u{FF4B}\u{FF45}\u{FF4E}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'token' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_fullwidth_verify() {
        // Fullwidth 'verify': U+FF56 U+FF45 U+FF52 U+FF49 U+FF46 U+FF59
        let text = "\u{FF56}\u{FF45}\u{FF52}\u{FF49}\u{FF46}\u{FF59}";
        let findings = detector().detect(text, &opts());
        assert!(!findings.is_empty(), "fullwidth 'verify' must be blocked");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    // --- Fullwidth must-allow tests (non-target words must not be blocked) ---

    #[test]
    fn no_fp_fullwidth_hello() {
        // Fullwidth 'hello': U+FF48 U+FF45 U+FF4C U+FF4C U+FF4F
        let text = "\u{FF48}\u{FF45}\u{FF4C}\u{FF4C}\u{FF4F}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "fullwidth 'hello' must NOT be blocked, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_fullwidth_the() {
        // Fullwidth 'the': U+FF54 U+FF48 U+FF45
        let text = "\u{FF54}\u{FF48}\u{FF45}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "fullwidth 'the' must NOT be blocked, got: {:?}",
            findings
        );
    }

    // --- Red-team round-5: Latin small-capital / IPA-modifier laundering ---

    #[test]
    fn blocks_small_cap_paypal() {
        // ᴘᴀʏᴘᴀʟ = U+1D18 U+1D00 U+028F U+1D18 U+1D00 U+029F
        // These small-cap Latin letters are NOT decomposed by NFKC or skeleton()
        // but visually spell "paypal" — must be blocked as a spoof
        let text = "\u{1D18}\u{1D00}\u{028F}\u{1D18}\u{1D00}\u{029F}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "small-cap 'ᴘᴀʏᴘᴀʟ' laundering must be flagged, got: {:?}",
            findings
        );
        assert_eq!(findings[0].rule_id, "homoglyph.mixed_script_confusable");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_small_cap_login() {
        // ʟᴏɢɪɴ — small-cap "login"
        let text = "\u{029F}\u{1D0F}\u{0262}\u{026A}\u{0274}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "small-cap 'ʟᴏɢɪɴ' laundering must be flagged"
        );
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_small_cap_account() {
        // ᴀᴄᴄᴏᴜɴᴛ — small-cap "account"
        let text = "\u{1D00}\u{1D04}\u{1D04}\u{1D0F}\u{1D1C}\u{0274}\u{1D1B}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "small-cap 'ᴀᴄᴄᴏᴜɴᴛ' laundering must be flagged"
        );
    }

    #[test]
    fn no_fp_small_cap_hello() {
        // ʜᴇʟʟᴏ — small-cap "hello" (NOT in HIGH_VALUE_TARGETS) must allow
        let text = "\u{029C}\u{1D07}\u{029F}\u{029F}\u{1D0F}";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "small-cap 'ʜᴇʟʟᴏ' (hello) must NOT be blocked, got: {:?}",
            findings
        );
    }

    #[test]
    fn blocks_partial_small_cap_paypal() {
        // Mixed: small-cap ᴘ + ASCII "aypal" — cross-script confusable in Latin token
        let text = "\u{1D18}aypal";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "partial small-cap 'ᴘaypal' laundering must be flagged"
        );
    }

    // --- Round 6: Greek scientific notation must-allow (TDD RED before fix) ---

    #[test]
    fn no_fp_greek_alpha_particle() {
        // Exact red-team repro: α-particle — α (U+03B1) folds to 'a', "particle" not a target
        let text = "\u{03B1}-particle";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "α-particle must NOT be flagged (legitimate scientific notation), got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_gamma_ray() {
        // γ-ray — γ (U+03B3)
        let text = "\u{03B3}-ray";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "γ-ray must NOT be flagged (legitimate scientific notation), got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_sigma_bond() {
        // σ-bond — σ (U+03C3)
        let text = "\u{03C3}-bond";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "σ-bond must NOT be flagged (legitimate scientific notation), got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_rho_meson() {
        // ρ-meson — ρ (U+03C1) folds to 'p'
        let text = "\u{03C1}-meson";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "ρ-meson must NOT be flagged (legitimate scientific notation), got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_nu_beam() {
        // ν-beam — ν (U+03BD) folds to 'v'
        let text = "\u{03BD}-beam";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "ν-beam must NOT be flagged (legitimate scientific notation), got: {:?}",
            findings
        );
    }

    // --- Round 7 defect 1: whole-script Cyrillic 'paypal' bypass via palochka U+04CF ---

    #[test]
    fn blocks_cyrillic_palochka_paypal() {
        // р(U+0440) а(U+0430) у(U+0443) р(U+0440) а(U+0430) ӏ(U+04CF lowercase palochka)
        // visually spells "paypal" but ӏ must fold to 'l' for detection to work
        let text = "\u{0440}\u{0430}\u{0443}\u{0440}\u{0430}\u{04CF}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "whole-script Cyrillic 'рауралӏ' (paypal via palochka U+04CF) must be blocked, got: {:?}",
            findings
        );
        assert_eq!(findings[0].severity, Severity::Block);
    }

    // --- Round 7 defect 2: false positive α-account, ν-bank, γ-secure ---

    #[test]
    fn no_fp_greek_alpha_account() {
        // α-account: Greek letter + separator + bare ASCII target word
        // The confusable (α) is in a DIFFERENT segment from the target word "account"
        let text = "\u{03B1}-account";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "α-account must NOT be flagged (confusable in different segment from target), got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_nu_bank() {
        // ν-bank: Greek letter + separator + bare ASCII target word
        let text = "\u{03BD}-bank";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "ν-bank must NOT be flagged (confusable in different segment from target), got: {:?}",
            findings
        );
    }

    #[test]
    fn no_fp_greek_gamma_secure() {
        // γ-secure: Greek letter + separator + bare ASCII target word
        let text = "\u{03B3}-secure";
        let findings = detector().detect(text, &opts());
        assert!(
            findings.is_empty(),
            "γ-secure must NOT be flagged (confusable in different segment from target), got: {:?}",
            findings
        );
    }

    // --- Round 8: modifier-letter laundering (TDD RED — will fail before fix) ---

    #[test]
    fn blocks_modifier_letter_google() {
        // ᵍᵒᵒᵍˡᵉ = U+1D4D U+1D52 U+1D52 U+1D4D U+02E1 U+1D49
        // Modifier-letter superscripts: NFKC folds to "google" but skeleton() may not
        // These are Latin-script alphabetic chars but their per-char skeleton stays non-ASCII
        let text = "\u{1D4D}\u{1D52}\u{1D52}\u{1D4D}\u{02E1}\u{1D49}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "modifier-letter 'ᵍᵒᵒᵍˡᵉ' laundering must be flagged, got: {:?}",
            findings
        );
        assert_eq!(findings[0].rule_id, "homoglyph.mixed_script_confusable");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_modifier_letter_apple_prefix() {
        // ᵃpple = U+1D43 + "pple"
        // Single modifier-letter prefix: NFKC fold of token is "apple" (target)
        let text = "\u{1D43}pple";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "modifier-letter prefix 'ᵃpple' laundering must be flagged, got: {:?}",
            findings
        );
        assert_eq!(findings[0].rule_id, "homoglyph.mixed_script_confusable");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_parenthesized_latin_paypal() {
        // ⒫⒜⒴⒫⒜⒧ = U+24AB U+249C U+24B4 U+24AB U+249C U+24A7
        // Parenthesized Latin: not alphabetic (c.is_alphabetic()==false) so Gate 2 skips them
        // but NFKC folds each to "(letter)" so alpha-only extract gives "paypal"
        let text = "\u{24AB}\u{249C}\u{24B4}\u{24AB}\u{249C}\u{24A7}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "parenthesized 'paypal' laundering must be flagged, got: {:?}",
            findings
        );
        assert_eq!(findings[0].rule_id, "homoglyph.mixed_script_confusable");
        assert_eq!(findings[0].severity, Severity::Block);
    }

    // --- Round 9: non-skeleton-folding Cyrillic lookalike bypass (defect: к U+043A dropped) ---

    #[test]
    fn blocks_cyrillic_a_and_non_folding_k_bank() {
        // bаnк: b(ASCII) + а(Cyrillic U+0430, folds→'a') + n(ASCII) + к(Cyrillic U+043A, no ASCII fold)
        // Rule-4 path: cross_script_confusables>=1 (from а). In matches_high_value_target_for_rule4,
        // к has no ASCII skeleton so it was silently dropped, shortening "bank"→"ban" → ALLOW (bypass).
        // Fix: when segment has_confusable AND has a non-folding non-ASCII char, fail closed → BLOCK.
        let text = "b\u{0430}n\u{043A}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "bаnк (Cyrillic а + non-folding к) must be blocked as a 'bank' spoof, got: {:?}",
            findings
        );
        assert_eq!(findings[0].severity, Severity::Block);
    }

    #[test]
    fn blocks_cyrillic_mixed_folding_nonfolding_bank_variants() {
        // Variants where a folding Cyrillic char + a non-folding Cyrillic char combine to spoof "bank".
        // All must be blocked.

        // аbnк: а(folds→'a') + b(ASCII) + n(ASCII) + к(non-folding)
        let text = "\u{0430}bn\u{043A}";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "аbnк (leading Cyrillic а + trailing non-folding к) must be blocked, got: {:?}",
            findings
        );

        // bаnк with context (in sentence)
        let text2 = "visit b\u{0430}n\u{043A} now";
        let findings2 = detector().detect(text2, &opts());
        assert!(
            !findings2.is_empty(),
            "bаnк in sentence must be blocked, got: {:?}",
            findings2
        );
    }

    // Controls: mixed-script spoofs on HIGH_VALUE_TARGETS must still block

    #[test]
    fn still_blocks_greek_alpha_in_account() {
        // α (ASCII-folding Greek) in "account" — the token skeleton contains "account"
        let text = "\u{03B1}ccount"; // α + "ccount" → skeleton "account"
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "Greek α replacing 'a' in 'account' must still be blocked, got: {:?}",
            findings
        );
    }

    #[test]
    fn still_blocks_greek_rho_in_paypal() {
        // ρ (U+03C1, folds to 'p') in paypal → "ρaypal" — skeleton "paypal" is a target
        let text = "\u{03C1}aypal";
        let findings = detector().detect(text, &opts());
        assert!(
            !findings.is_empty(),
            "Greek ρ replacing 'p' in 'paypal' must still be blocked, got: {:?}",
            findings
        );
    }
}

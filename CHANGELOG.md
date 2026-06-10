# Changelog

All notable changes to ioguard are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); versions follow [SemVer](https://semver.org).

## [0.1.1] - 2026-06-10

Release-pipeline fix. v0.1.0 was tagged but published **no downloadable
artifacts** — the release workflow referenced the wrong binary name and failed
before upload. This release makes `git tag v*` actually publish.

### Fixed
- **Release artifacts now publish.** The GitHub release for a version tag now
  builds and attaches the `ioguard` binary plus its `.sha256` checksum. The
  binary name is derived structurally from `cargo metadata`, so it stays correct
  across renames (no hardcoded path to drift). A tag-vs-`CARGO_PKG_VERSION` gate
  refuses to release a tag whose version doesn't match the crate.
- **CI no longer flags ioguard's own detector patterns as leaked secrets.** The
  secret-detector's built-in API-key/PEM patterns and the `must-block` test
  corpus are fingerprint-allowlisted, so the secret-scan and SBOM jobs pass on
  pull requests (previously every PR went red, blocking dependency updates).

### Security
- No detector behavior changed. ioguard scans exactly as in 0.1.0; this release
  only repairs the release and CI pipelines.

## [0.1.0] - 2026-06-06

First release. A deterministic LLM-I/O safety scanner — CLI, Rust library, and C-ABI from
one detection core. No ML, no network, sub-millisecond per typical I/O pair.

### Detectors
- **secret** — API keys (Anthropic, OpenAI, AWS incl. ASIA/AROA, GitHub incl. gho_/ghs_/pat,
  Google, Stripe incl. rk_live_, …), PEM/GPG private keys, Luhn-validated card PANs with a
  published-test-card allowlist.
- **unicode_tags** — U+E0000–E007F Tag-block instruction smuggling; validated RGI
  subdivision-flag carve-out (no false positives on flag emoji).
- **zero_width** — invisible / `Default_Ignorable` format characters (incl. interlinear
  annotation, Hangul fillers, Khmer signs) used to fragment secrets/instructions;
  emoji-ZWJ and keycap aware.
- **bidi** — Trojan-Source bidirectional controls; structural BCP-47 locale exemption.
- **homoglyph** — UTS#39 mixed-script + NFKC confusable spoofs (Cyrillic/Greek/fullwidth/math),
  with a single-script guard and a curated high-value target wordlist.
- **special_token** — chat-template / control tokens (ChatML, Llama3, Gemini, Mistral,
  Cohere, Falcon, FIM); case-sensitive and whitespace/NFKC aware to avoid false positives.

### Surfaces
- `ioguard scan` CLI — stdin → Contract-A JSON on stdout; exit codes `0` allow / `10` warn / `20` block.
- `ioguard-core` Rust library — `scan(text, &opts) -> ScanResult`.
- `ioguard-ffi` C-ABI — `ioguard_scan` / `ioguard_free`, panic-isolated, cbindgen header.

### Quality
- Conformance corpus as a CI gate (`corpus/must-block`, `corpus/must-allow`).
- Hardened across six adversarial red-team rounds (the last two fully autonomous) to
  **zero in-scope high-severity findings**.
- Property-based detection (Default_Ignorable, Extended_Pictographic, UTS#39 skeleton,
  structural BCP-47) over fixed codepoint lists where possible.

### Known limitations (tracked for v1.1)
- A generic high-entropy hex/base64 bearer-token rule is deferred (needs an entropy detector
  to avoid git-SHA false positives).
- Lower-severity coverage gaps remain in the enumeration long tail (additional sibling
  credential prefixes, further invisible-character families).

[0.1.0]: https://github.com/peiman/ioguard/releases/tag/v0.1.0

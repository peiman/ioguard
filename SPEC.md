# Build Spec — `ioguard`

**A fast, deterministic, language-neutral LLM I/O safety + secret-scanning SSOT.**

| | |
|---|---|
| **Repo** | `peiman/ioguard` (new) · **public** · MIT OR Apache-2.0 |
| **Language** | Rust (cargo workspace) · scaffold on **ckeletin-rust** |
| **Builder** | workhorse (parallel-agent workflow) |
| **Status** | proposed → build |
| **Depends on** | nothing (pure primitive) |
| **Consumed by** | vaultmind vault-gate (via CLI), `agent-chat` (via library), any LLM boundary |
| **Contracts** | result schema = Contract A in `mesh-architecture-and-contracts.md` |

---

## 1. Why it exists (positioning)

Every serious LLM-guard today (LLM Guard, Rebuff, NeMo, Lakera/Cisco, LlamaFirewall, guardrails-ai,
Presidio) is **Python + ML-dependent** for its core decisions. Secret scanners
(gitleaks/trufflehog/detect-secrets) have **zero** coverage of Unicode smuggling or LLM-token
anomalies. No one ships a fast, compiled, deterministic, language-neutral binary that unifies
**secret redaction + Unicode-smuggling defense + token-structure checks**. That is ioguard's slot.

**Positioning:** *the deterministic pre-flight layer — runs before your ML classifier, no Python, no
model weights, no network, sub-millisecond per I/O pair.* It is **complementary** to the ML guards
(they are the semantic layer; ioguard is the pattern/structure layer that fires first and cheapest),
and it can hand its findings to a downstream probabilistic classifier as features.

Urgency is real: GlassWorm (Oct 2025) used invisible-Unicode to compromise 35k+ VSCode installs;
~46k OpenAI keys leak/month. The only existing Rust attempt (`jeffskafi/llm-firewall`) is 5 commits,
no releases — the position is unoccupied.

## 2. Scope

**ioguard scans a blob of text headed INTO or OUT OF an LLM and returns a verdict + findings.** It is
direction-aware (the caller says `input` or `output`); some rules only apply to one direction.

### In scope — v1 (deterministic, ship first)

| Rule category | Det. | Dir | Technique | Reuse | FP control |
|---|---|---|---|---|---|
| `secret.*` | ✅ | both | provider-prefix regex (Anthropic `sk-ant-api03-`, OpenAI embeds `T3BlbkFJ`, AWS `AKIA`, GitHub `ghp_`, Stripe `sk_live_`), PEM `-----BEGIN … PRIVATE KEY-----`, generic 40–64 hex/base64 bearer w/ length gate, card PAN = IIN-prefix + **Luhn** | seed from **gitleaks** TOML rules (Apache-2.0) | provider prefixes ≈ 0 FP; PAN requires IIN prefix **and** 4-4-4-4 grouping; **allowlist Stripe test cards** (`4242…`, `378282…`, etc.) |
| `unicode_tags` | ✅ **0 FP** | both | one UTF-8 regex `\xF3\xA0[\x80\x81][\x80-\xBF]` for U+E0000–E007F Tag block; **multi-pass** strip + UTF-16 surrogate (U+D800–DFFF) reconstruction defense (per AWS) | — (build, ~20 lines) | Tag block has no legit prose use → zero FP |
| `zero_width` | ✅ | both | flag U+200B, U+200C, U+200D, U+FEFF, U+00AD | — | **allow ZWJ (U+200D) when flanked by emoji** codepoints (emoji sequences) |
| `bidi` | ✅ | both | flag U+202A–202E, U+2066–2069, U+200E/200F (Trojan Source / CVE-2021-42574) | — | **allow in explicitly-RTL locale** (configurable) |
| `homoglyph` | ✅ | both | NFKC normalize + re-scan; OR UTS#39 confusables on mixed-script strings | **`unicode-security`**, **`unicode-normalization`** crates | flag only when normalized form differs meaningfully; full TR39 folding |
| `special_token` | ✅ | input | regex list of control tokens: `<\|im_start\|>` `<\|im_end\|>` `<\|system\|>` `[INST]` `[/INST]` `<<SYS>>` `<s>` `</s>` `<tool_call>` `<\|endoftext\|>` | curated list (maintainable) | **scope to untrusted-content channel only** — never scan the app's own template; FP drops to low |

### In scope — v1.1 (partial-determinism, ship after v1 lands)

| Rule | Dir | Technique | FP control |
|---|---|---|---|
| `exfil_marker` | output | external image/link URL + high-entropy path/query or `data/secret/token/key`-named param | domain allowlist; entropy gate (AST-md parse is the robust upgrade) |
| `encoding_smuggle` | both | base64/hex/ROT13 **decode-and-rescan**; flag only if decoded content trips another rule | **never** flag raw structural base64 (data URIs, JWTs are everywhere) |
| `token_dos` | input | max whitespace-free run > N (default 500); est tokens (`len/4`) > cap (default 32k); n-gram repetition > 40% | generous caps; repetition exempt for code/poetry contexts |
| `pii.*` | both | email / E.164 phone / SSN regex | **DISABLED BY DEFAULT** — this owner's vault *wants* personal info; opt-in via policy |

### Explicitly OUT of scope (deferred to a probabilistic layer — do NOT build here)

- **Semantic prompt injection / jailbreaks** ("ignore previous instructions" phrased novelly,
  "you are DAN", role-play bypasses). Novelty defeats static filters by definition; needs an ML guard
  (Llama Guard / Rebuff / fine-tuned classifier). ioguard runs *before* it as the cheap pre-filter.
- **Glitch-token detection** (SolidGoldMagikarp class) — requires model weights. Ship a **hook** for a
  configurable per-model known-bad-token exact-match list (off by default); do not ship the list.

## 3. Architecture

Cargo workspace (each crate is an independently testable slice — good for parallel agents):

```
ioguard/
  crates/
    ioguard-core/     # the detection engine + Verdict/Finding types + ruleset loader. NO I/O.
    ioguard-cli/      # thin CLI over core. Single static binary (musl target). stdin → JSON.
    ioguard-ffi/      # C-ABI (cbindgen, repr(C), extern "C", panic isolation). cdylib + staticlib.
    ioguard-py/       # (optional, later) PyO3 + maturin wheel.
  rules/              # the declarative ruleset (TOML) — the SSOT for patterns/allowlists/thresholds.
  corpus/             # conformance fixtures: must-block/ and must-allow/ (Contract D).
```

**Core API (the contract the whole thing hangs on):**

```rust
pub enum Verdict { Allow, Warn, Block }
pub struct Finding {
    pub rule_id: String,      // e.g. "secret.anthropic_key"
    pub category: Category,    // Secret | UnicodeTags | ZeroWidth | Bidi | Homoglyph | SpecialToken | Exfil | Encoding | TokenDos | Pii
    pub severity: Severity,    // Block | Warn
    pub direction: Direction,  // Input | Output | Both
    pub span: (usize, usize),  // byte offsets into the input
    pub preview: String,       // first 8 chars + "…"  — NEVER the full secret
}
pub struct ScanResult { pub verdict: Verdict, pub findings: Vec<Finding>, pub stats: Stats }

pub fn scan(text: &[u8], opts: &ScanOptions) -> ScanResult;
// opts: direction, ruleset/policy, enabled categories, locale (for bidi), allowlists.
```

**Pure detection; the caller owns policy.** `verdict` = max severity across findings. ioguard ships a
default category→severity map in `rules/`, overridable by the caller. The vault-gate and chat both
REFUSE on `Block`; what to do with `Warn` is the caller's call.

**Ruleset** (`rules/*.toml`): each rule = `{ id, category, regex|codepoints, keywords?, entropy?,
severity, direction, allowlist }`. This file is the SSOT for "what is a secret / what is unsafe." Seed
the `secret.*` rules from gitleaks' Apache-2.0 set; author the Unicode/token rules.

## 4. Interfaces

### CLI (the cross-language boundary — vaultmind & any subprocess consumer)

```
ioguard scan [--direction input|output] [--policy <file>] [--format json] [--enable cat,cat] [--locale <bcp47>]
  reads stdin, writes the Contract-A JSON to stdout.
  exit: 0 allow · 10 warn · 20 block · >100 error.
ioguard redact ...   # (optional) emit the input with findings replaced by [REDACTED:<rule_id>]
ioguard rules        # list active rules
ioguard version
```

### Library (native consumers — the chat daemon links this)

`ioguard_core::scan(...)` as above. Re-exported through `ioguard-ffi` as:

```c
// C-ABI — panic-isolated (catch_unwind at the boundary), returns owned JSON string.
char* ioguard_scan(const uint8_t* text, size_t len, const char* opts_json);
void  ioguard_free(char* json);
```

The Go vault-gate uses the **CLI** (subprocess at note-create / pre-embed — low frequency, perfect).
The Rust chat daemon links the **library** (hot path, per-message, no subprocess). Same code = SSOT.

## 5. Quality bar (non-negotiable)

- **ckeletin-rust** scaffold; the Rust-equivalent of `task check` is green (fmt, clippy, test, deny).
- **TDD** — each detector lands test-first.
- **The conformance corpus is a CI gate** — every build runs `corpus/must-block` (all must `Block`)
  and `corpus/must-allow` (none may `Block`). Seed it with the fixtures in Contract D.
- **Zero FP on `unicode_tags`** — assert against emoji, CJK, accented Latin, math symbols.
- **Performance:** sub-millisecond per typical I/O pair; the `regex` crate's linear-time DFA (no
  catastrophic backtracking) is the foundation. No ML, no network, no Python at runtime.
- **No secret in logs/errors** — `preview` truncates; never print the full match.
- CLI ships as a **static binary** (musl) so subprocess consumers need no runtime deps.

## 6. Build slicing (for parallel agents)

Each is independent and testable in isolation; the pipeline composes them:

1. `ioguard-core` skeleton: `Verdict`/`Finding`/`ScanResult` types, ruleset loader, the `scan()`
   pipeline shell, the corpus harness. (Do first — others plug in.)
2. `secret.*` detector (+ corpus entries). Highest value.
3. `unicode_tags` detector (+ the multi-pass/surrogate defense + 0-FP corpus). Reference: Cisco
   skill-scanner PR #94 (23 tests).
4. `zero_width` + `bidi` detectors (+ emoji-ZWJ / RTL-locale gates).
5. `homoglyph` detector (NFKC + `unicode-security`).
6. `special_token` detector (curated list, untrusted-channel scoping).
7. `ioguard-cli` (stdin→JSON, exit codes, static build).
8. `ioguard-ffi` (C-ABI, panic isolation, cbindgen header).
9. v1.1 detectors: `exfil_marker`, `encoding_smuggle`, `token_dos`, `pii` (flag-gated).

## 7. Definition of done (how to report back)

v1 is done when:
- `ioguard scan` and `libioguard` build clean on `ckeletin-rust`'s `check`.
- The conformance corpus passes (must-block all blocked, must-allow none blocked).
- The Contract-A JSON schema is documented in the repo README and stable.
- A **integration smoke** passes: pipe a planted Anthropic key (`sk-ant-api03-…`) into
  `ioguard scan` → `verdict: block`; pipe ordinary prose → `verdict: allow`; pipe a Tag-Block-smuggled
  instruction → `verdict: block`.
- Repo is `peiman/ioguard`, public, dual-licensed, with a README stating the positioning + the schema.

**Report:** workhorse delivers the repo + a short completion note (what shipped, corpus pass count,
the smoke output, anything deferred). The vaultmind team verifies the corpus + the smoke before
wiring the vault-gate to it.

## 8. References (the SOTA scan, 2026-06-05)

- gitleaks rules (Apache-2.0): https://github.com/gitleaks/gitleaks · Luhn: https://en.wikipedia.org/wiki/Luhn_algorithm
- Unicode Tags smuggling: AWS https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/ · Cisco skill-scanner PR#94 https://github.com/cisco-ai-defense/skill-scanner/pull/94 · arXiv 2603.00164
- Special-token injection (ChatInject): https://arxiv.org/html/2509.22830v2 · https://blog.sentry.security/special-token-injection-sti-attack-guide/
- Homoglyph/Trojan Source: https://arxiv.org/html/2508.14070v1 · CVE-2021-42574
- Rust crates: `regex` https://docs.rs/regex · `unicode-security` https://lib.rs/crates/unicode-security · `unicode-normalization`
- Cross-language shipping (CLI + C-ABI, purego/CGO_ENABLED=0): https://blog.arcjet.com/calling-rust-ffi-libraries-from-go/
- Out-of-scope (semantic injection needs ML): OWASP LLM01 https://genai.owasp.org/llmrisk/llm01-prompt-injection/ · TokenBreak https://starai.cs.ucla.edu/papers/GehACL25.pdf

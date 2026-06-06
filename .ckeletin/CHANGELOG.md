# ckeletin Framework Changelog

## [0.2.16] - 2026-06-05

### Added
- **Machine-readable command catalog (`catalog` command) — CKSPEC-AGENT-006.**
  The CLI now self-reports its own command surface as structured data: a
  `catalog` command emits, through the OUT-002 envelope, an enumeration of every
  command, subcommand, and flag — derived from the **same clap tree the parser
  uses** (`Cli::command()`), so it cannot drift from the actual command set.
  - `ckeletin::catalog` (framework crate, re-exported via `infrastructure`):
    the `Catalog` / `CatalogCommand` / `CatalogFlag` types — the cross-impl
    schema agreed with ckeletin-go (required core `long`/`required`/`takes_value`
    per flag, `global_flags` once at top level, recursive `commands`; optional
    `short`/`description`/`default`/`possible_values` where clap derives them).
    Defining the schema as a shared framework type means a derived project
    cannot emit a wrong-shaped catalog.
  - `crates/cli/src/catalog.rs` (worked example, like `ping`/`version`): the
    clap → `Catalog` walk (clap is cli-only by architecture).
  Closes the rust side of spec issue #9 (both agents endorsed SHOULD@v0.8.0).
  Spec text + conformance mapping land separately (the spec gets updated with a
  proven implementation, per the two-impl gate).

### Fixed
- **`conform` recipes no longer error in consumer repos.** `conform` /
  `conform-refresh` / `conform-report` validate ckeletin-rust against its own
  spec and are **upstream-only** — but the recipes propagate via `.ckeletin/`,
  and a consumer has no `conformance/requirements.json` (it's project-owned, only
  in the framework repo). So `just conform` failed with "cannot read vendored
  spec" on every downstream repo (found while updating the triz consumer
  v0.2.2→v0.2.14). The recipes now detect a consumer — the upstream `repository`
  slug is absent from the root `Cargo.toml` once `just init` rewrites it, the
  same signal the `ckeletin-update` self-guard uses — and **no-op with an
  explanation (exit 0)** instead of erroring. Regression test:
  `.ckeletin/crate/tests/conform_guard.rs`.

## [0.2.14] - 2026-06-05

### Added (agent-drivable: hardening for autonomous maintenance)
The framework's update/diagnostic surface now speaks machine, so an autonomous
orchestrator can drive it without human-shaped prose, prompts, or guesswork.
- **`ckeletin-check-update json`** — emits `{"current","latest","update_available"}`
  (or `{"error":"no_upstream_remote",…}`). The trigger signal for a maintenance
  loop: poll, branch on `update_available`.
- **`ckeletin-doctor json`** — emits a single object: `framework_version`,
  `toolchain` (pinned/msrv/rustc), and `tools` as booleans. Machine preflight
  for "is this environment ready". Regression test in `doctor.rs`.
- **`ckeletin-update` structured verdict** — prints a final
  `CKELETIN_UPDATE_RESULT={…}` line on every exit path with
  `status` (`updated` / `compile_failed` / `check_failed`), `from`, `to`,
  `committed`, `rolled_back` — so a driver can decide rollback / fix / escalate
  without parsing prose.
- **Non-interactive `just init`** — honours `CKELETIN_ASSUME_YES=1` to skip the
  uncommitted-changes prompt for agent/CI use. In a non-interactive shell
  WITHOUT that var it now refuses (exit 1) rather than blocking on a prompt or
  silently discarding work.

All text/human output is unchanged (these are additive `format` params / env
opt-ins), so existing usage is unaffected.

## [0.2.13] - 2026-06-04

### Fixed
- **`ckeletin-update` now guards with the real gate (`just check`), not just
  `cargo check`.** `cargo check` builds only lib/bins, so it did NOT run the
  clippy lint set or tests that `just check` enforces — meaning a release that
  tightened the gate could **auto-commit a red `just check`** on a consumer's
  branch with no signal at update time (reported by workhorse, 2026-06-04). Now:
  - a non-compiling update still rolls back fully (unchanged);
  - an update that compiles but fails `just check` is **left in the working tree,
    uncommitted** (not rolled back), with guidance to fix the new violations and
    commit — so you can fix forward instead of silently landing a red gate.
  - `ckeletin-update-check-compatibility` likewise runs `just check` now, so it
    surfaces tightened-gate failures *before* you update.

### Changed
- **`float_cmp` is now scoped to library/binary code, not tests.** The hardened
  clippy gate (0.2.11) ran `float_cmp` over `--all-targets`, flagging idiomatic
  exact-sentinel test assertions like `assert_eq!(score, 0.0)` (workhorse hit
  ~18 such sites). It is now a separate `--lib --bins` pass, keeping the safety
  for real logic without fighting correct test assertions. The other hardened
  lints (cast safety, etc.) remain on all targets — they caught a real
  truncation bug downstream.

### Upgrading from 0.2.11 (note for adopters)
The 0.2.11 hardened clippy gate may flag pre-existing cast sites in your code on
the first `just check` after updating. Fix forward: use `try_from` (returning an
error) where a value can genuinely overflow or lose sign; add a reasoned
`#[allow(clippy::cast_…)]` with a one-line rationale where the conversion is safe
by construction (e.g. a bounded counter). Run `just ckeletin-update-check-compatibility`
first to preview what the new gate will flag.

## [0.2.12] - 2026-06-04

### Added
- **Fuzzing worked example with bolero.** Chose
  [bolero](https://github.com/camshaft/bolero) because it is the only mainstream
  Rust fuzzer whose targets run on **stable** (the scaffold's pinned toolchain) —
  unlike cargo-fuzz, which needs nightly.
  - `crates/domain/tests/fuzz_ping.rs` — the `ping` worked example's fuzz
    counterpart: feeds arbitrary messages into `PingResult` and asserts `Display`
    and serde round-trip never panic for any input. It runs as an ordinary
    `cargo test` (bounded, deterministic, generative) on stable, so it is a
    **regression guard inside `just check`** — every PR gets fuzz-generated
    coverage with no nightly and no extra tooling.
  - `ckeletin-fuzz` recipe — exercises the bolero targets on stable
    (`cargo test --test fuzz_ping`), for iterating on a target directly.
  - `bolero` added as a **dev-dependency** (does not relax domain's runtime
    "only serde" boundary); a `[profile.fuzz]` is defined for bolero.
  - `ckeletin-doctor` reports cargo-bolero.
  - **Deliberately not wired:** coverage-guided *active* fuzzing (bolero's
    libfuzzer engine) needs nightly AND a dedicated fuzz crate excluded from the
    workspace — its sancov instrumentation otherwise leaks into sibling test
    binaries (the cli integration tests) and fails to link on both macOS arm64
    and Linux. Documented in the `ckeletin-fuzz` recipe as the next step for
    teams that want continuous coverage-guided fuzzing.

## [0.2.11] - 2026-06-04

### Added
- **Static analysis hardening (SAST).** Research showed dedicated SAST adds
  little marginal value in Rust beyond clippy + cargo-deny (memory-safety
  removes the bug classes tools like semgrep target; cargo-audit duplicates
  cargo-deny's advisory DB). So this takes the two genuinely additive steps:
  - **Hardened `ckeletin-clippy`** — denies a curated set of security/correctness
    lints on top of `-D warnings`: numeric-cast safety
    (`cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap`,
    `cast_precision_loss`), float pitfalls (`float_cmp`, `lossy_float_literal`),
    and footguns (`dbg_macro`, `todo`, `unimplemented`, `mem_forget`,
    `rc_buffer`, `verbose_file_reads`, `wildcard_dependencies`). Gates via
    `just check` and (SSOT) the lefthook pre-commit clippy hook now calls
    `just ckeletin-clippy` so both enforce the identical set.
  - **`ckeletin-geiger` recipe** — reports the `unsafe` surface across the
    dependency tree with [cargo-geiger](https://github.com/geiger-rs/cargo-geiger)
    (`--forbid-only`). ADVISORY ONLY — an unsafe count is a metric, not a gate,
    so it never blocks `just check`.
  - `ckeletin-doctor` reports cargo-geiger presence.
  Deliberately did NOT add cargo-audit (redundant with cargo-deny) or semgrep
  (thin Rust ruleset, low marginal value).

## [0.2.10] - 2026-06-04

### Added
- **SBOM generation + vulnerability scanning (supply-chain readiness).**
  - `ckeletin-sbom` recipe — generates `sbom.cdx.json`, a CycloneDX 1.5 SBOM of
    the CLI binary's full dependency graph, using
    [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo) (the
    official OWASP CycloneDX cargo plugin; stable toolchain, no nightly).
  - `ckeletin-sbom-scan` recipe — generates then scans the SBOM with
    [grype](https://github.com/anchore/grype), failing on High severity or above.
  - Both standalone (external tools, not in `just check`). `ckeletin-doctor`
    reports cargo-cyclonedx + grype presence. Generated `*.cdx.json` are
    gitignored.
  - Worked example (project-owned): a `sbom` CI job that generates + scans and
    uploads the SBOM as a build artifact for compliance/consumers.
  Chose the Rust-native OWASP generator over syft for a leaner footprint (one
  external binary) while keeping grype for parity with ckeletin-go's scanner.

## [0.2.9] - 2026-06-04

### Added
- **Secret scanning with gitleaks (CKSPEC-ENF-001).** Detects hardcoded
  credentials committed to the repo, using the industry-standard
  [gitleaks](https://github.com/gitleaks/gitleaks) (MIT, single static binary).
  - `ckeletin-secrets` recipe — scans the working tree. Standalone, not part of
    `just check` (gitleaks is an external non-cargo tool, so a missing gitleaks
    never blocks the cargo gate).
  - `.ckeletin/configs/gitleaks.toml` — framework default config (extends the
    built-in ruleset, excludes `target/`); override via a root `.gitleaks.toml`.
  - `ckeletin-doctor` now reports gitleaks presence.
  - Worked examples (project-owned, kept/replaced by adopters): a lefthook
    pre-commit staged scan that skips cleanly when gitleaks is absent but fails
    on a real secret, and a `secret-scan` CI job that scans full git history via
    the gitleaks **CLI** (not the commercial gitleaks-action).
  Mirrors ckeletin-go's secret scanning.

## [0.2.8] - 2026-06-04

### Added
- **`ckeletin-doctor` recipe.** Reports the development environment — framework
  version, pinned toolchain + MSRV (read from `rust-toolchain.toml` / `Cargo.toml`,
  so it stays SSOT) and installed `rustc`, plus presence of the tools the
  framework depends on (`cargo-deny`, `cargo-llvm-cov`, optional `cargo-nextest`,
  `just`, and the rustfmt/clippy components). Informational only — always exits 0,
  so it is intentionally not part of `just check`. Mirrors ckeletin-go's
  `task doctor`. Smoke test: `.ckeletin/crate/tests/doctor.rs`.
- **`ckeletin-version` recipe.** Prints the framework version (parity with
  ckeletin-go's `task version`).

### Notes
- Remaining ckeletin-go tasks are deliberately not ported. The `validate:*`
  ADR-enforcement suite is already achieved at compile time (trybuild violation
  tests + `framework_purity`) and by `conform`; the `check:*`/`test:*`/`build:*`
  variants collapse into the single `check` gateway and standard cargo; and
  GoReleaser/`generate:config:*`/`tidy` are Go-toolchain specific. Heavier
  capabilities (secret scanning, SAST, SBOM, fuzzing, benchmarks, `setup`) remain
  open decisions rather than silent external-tool dependencies.

## [0.2.7] - 2026-06-04

### Added
- **`ckeletin-update-check-compatibility` recipe.** Applies the upstream
  `.ckeletin/` to the working tree, runs `cargo check --workspace`, then
  restores the committed framework via a trap (interrupt-safe) — letting an
  adopter confirm an update compiles against their code without keeping it.
  Brings the Rust framework to parity with ckeletin-go's
  `task ckeletin:update:check-compatibility`. No import rewriting is needed
  (Rust references crates by name, not an embedded module path).
- **Upstream self-guard on the update recipes.** `ckeletin-update`,
  `ckeletin-update-dry-run`, and `ckeletin-update-check-compatibility` now
  short-circuit (exit 0 with a message) when run inside the ckeletin-rust
  upstream repo itself, detected via the workspace `repository` slug in the
  root `Cargo.toml` (`just init` rewrites it for derived projects). Mirrors
  ckeletin-go's go.mod module-path guard. Regression test:
  `.ckeletin/crate/tests/update_guard.rs`.

### Changed
- The upstream remote URL and identity slug are now SSOT `just` variables
  (`ckeletin_upstream_url`, `ckeletin_upstream_slug`) instead of being
  hardcoded across the update recipes.

## [0.2.6] - 2026-06-04

### Added
- **Anchored conformance evidence (CKSPEC-ENF-008).** `just conform` now
  exits non-zero on any `met` requirement that has no automated check, no
  violation test, and no written `violation_evidence` — an unbacked "met"
  can no longer pass the gate or reach the published report. The gate
  (`lacks_anchor`) runs after the completeness check; unit tests
  `anchored_met_passes` / `unanchored_met_is_rejected` prove it.
- **Published machine-readable conformance report (CKSPEC-ENF-010).** The
  generator projects `conformance-mapping.toml` into a deterministic
  `conformance-report.json` at the repo root — sorted requirement keys,
  alphabetical fields, **no timestamp** — so it is byte-stable and a spec
  repo can aggregate it instead of hand-authoring (the aggregator stamps
  the fetch date). `just conform` regenerates it in memory and **fails on
  drift** (sync-check); `just conform-report` rewrites it. Schema mirrors
  ckeletin-go's report (`implementation`, `requirements`, `spec_version`,
  `summary`). Unit tests `report_projection_is_deterministic` /
  `sync_check_detects_drift`.
- `conform-report` recipe in `.ckeletin/Justfile` — regenerate the
  published report after editing the mapping.

### Notes
- CKSPEC-ENF-009 (conformance gate on release) is wired at the project
  level, not the framework level: a tag-triggered `release.yml` gates its
  publish job on the `conform` job, and a scheduled `spec-drift.yml`
  watches the live upstream spec. These ship as worked examples adopters
  keep or replace, like `ci.yml`.

## [0.2.5] - 2026-06-03

### Added
- **Build identity (`build_info::BuildInfo`).** A prefix-agnostic framework
  primitive that surfaces the git provenance baked into a binary at compile
  time — version + commit + date + dirty — rendered by `version_line()`
  (mirrors ckeletin-go's `--version`: `"<version>, commit <commit>, built
  <date> (dirty)"`). The scaffold ships the worked example of consuming it:
  `crates/cli/build.rs` bakes the identity (one atomic `git describe --dirty`,
  so there is no false-clean gap; degrades to `unknown` on any git failure) and
  a `version` command renders it in human + JSON, with `--version` wired to the
  same formatter. Build-identity surfacing only; runtime staleness checking is
  left to the adopter (out of the shared cross-language contract). First
  consumer: workhorse (SH-004). Implements CKSPEC-OUT-006.

## [0.2.4] - 2026-05-31

### Changed
- The audit log (CKSPEC-OUT-004) now defaults to a stable per-user location
  instead of `./logs/` relative to the working directory. A relative
  `log_file_path` is anchored under `~/.config/<app>/` by default (XDG-style,
  uniform on every platform including macOS). New `log_location` config field:
  `"config"` (default) or `"platform"` (the OS-native app-data dir, e.g.
  `~/Library/Application Support/<app>` on macOS). An absolute `log_file_path`
  still overrides entirely. Resolution is dependency-free (env vars only — no
  new crates, no copyleft). The first-run notice prints the resolved path.

## [0.2.3] - 2026-05-29

### Changed
- Audit logging (CKSPEC-OUT-004) is now **on by default**
  (`Config.log_file_enabled` defaults to `true`), and
  `Output::success`/`message`/`error` shadow-log the *rendered data*, not
  just the command name — so the audit stream contains what the user saw.
  Downstream projects receive this on `just ckeletin-update` and will start
  writing `logs/app.log` by default; opt out with `log_file_enabled = false`
  (or the `--no-audit` flag if the consumer wires it into its CLI).

### Fixed
- `just init <name>` produced a non-compiling, un-committed project.
  The strip-demo step deleted `ping` (the only subcommand), leaving an
  empty `Commands` enum the entry point could not match exhaustively,
  and a `sed '/ping/Id'` line delete mangled the integration-test file
  into invalid Rust. init now keeps `ping` as the renamed worked
  example (as the ckeletin-go scaffold does) and verifies with
  `cargo check --all-targets`. The `init_smoke` test now builds and
  tests the initialized project, and CI gates it (upstream-only).
  Fixes #1.

### Security
- Bumped `rustls-webpki` to 0.103.13 (RUSTSEC-2026-0104: reachable
  panic parsing certificate revocation lists).

## [0.2.2] - 2026-04-22

### Added
- `Output::message(command, msg, writer)` — emit a human-addressed
  success response with no structured data. Human mode writes the
  message with a trailing newline; JSON mode wraps it in an
  envelope with `data: {"message": msg}` (structured, not a raw
  string blob in the data slot). Replaces the common wart of
  passing `&format!("...")` to `Output::success` for "no data to
  report" success paths.

### Spec alignment
- Neither CKSPEC-OUT-003 nor CKSPEC-OUT-005 forbade the prior
  pattern — it produced structurally valid envelopes — but the
  structure was inconsistent. `Output::message` formalizes the
  no-data-success shape so downstream consumers can rely on
  `data.message` always being a string.

## [0.2.0] - 2026-04-14

### Added
- Extracted framework library into `.ckeletin/crate/`
- Output, config, logging, process modules from infrastructure
- Framework update mechanism (`just ckeletin-update`)
- Init flow (`just init name=<name>`)
- Violation test templates in `.ckeletin/tests/violations/`
- Two-level Justfile: framework tasks in `.ckeletin/Justfile`

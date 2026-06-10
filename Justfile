set allow-duplicate-recipes

import '.ckeletin/Justfile'

binary_name := "ioguard"

# Single gateway — all checks
check: ckeletin-check test ckeletin-health
    @echo "All checks passed."

# Run tests
test:
    cargo nextest run --workspace 2>/dev/null || cargo test --workspace

# Auto-format all code
fmt:
    cargo fmt --all

# Run tests with coverage
coverage:
    cargo llvm-cov --workspace --fail-under-lines 85

# Build release binary
build:
    cargo build --release

# Override framework recipe: ioguard's CLI crate is at crates/ioguard-cli/
# (framework assumes crates/cli/). See .ckeletin/Justfile for the original.
ckeletin-sbom:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
        echo "Error: cargo-cyclonedx not found. Install: cargo install cargo-cyclonedx --locked"
        exit 1
    fi
    cargo cyclonedx --format json --spec-version 1.5
    cp crates/ioguard-cli/ioguard-cli.cdx.json sbom.cdx.json
    find crates .ckeletin -name '*.cdx.json' -delete
    echo "Wrote sbom.cdx.json (CycloneDX 1.5)"

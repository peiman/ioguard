#!/usr/bin/env bash
set -euo pipefail

NAME="${1:?Usage: just init name=<project-name>}"

# Validate name (lowercase, hyphens, no spaces)
if [[ ! "$NAME" =~ ^[a-z][a-z0-9-]*$ ]]; then
    echo "Error: name must be lowercase alphanumeric with hyphens (e.g., 'my-project')"
    exit 1
fi

# Pre-flight: warn about uncommitted changes. Automatable: set
# CKELETIN_ASSUME_YES=1 to proceed without a prompt (for agent/CI use). In a
# non-interactive shell without that var we REFUSE rather than silently discard
# uncommitted work.
if [ -d .git ] && ! git diff --quiet 2>/dev/null; then
    echo "Warning: uncommitted changes exist. Init resets git history — uncommitted work will be lost."
    if [ "${CKELETIN_ASSUME_YES:-}" = "1" ]; then
        echo "CKELETIN_ASSUME_YES=1 — proceeding without prompt."
    elif [ -t 0 ]; then
        read -p "Continue? (y/N) " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Aborted."
            exit 0
        fi
    else
        echo "Error: non-interactive shell and CKELETIN_ASSUME_YES is not set —" \
             "refusing to discard uncommitted changes. Set CKELETIN_ASSUME_YES=1 to proceed."
        exit 1
    fi
fi

echo "Initializing scaffold as: $NAME"

# Portable sed -i (macOS uses BSD sed, Linux uses GNU sed)
sedi() {
    if sed --version 2>/dev/null | grep -q GNU; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

# 1. Set binary name and replace all ckeletin-rust references in CLI crate
sedi "s/name = \"ckeletin-rust\"/name = \"$NAME\"/" crates/cli/Cargo.toml
sedi "s/ckeletin-rust/$NAME/g" crates/cli/src/root.rs

# 2. Update workspace metadata
sedi "s|peiman/ckeletin-rust|peiman/$NAME|g" Cargo.toml

# 3. Update Justfile binary name
sedi "s/binary_name := \"ckeletin-rust\"/binary_name := \"$NAME\"/" Justfile

# 4. Update env prefix in main.rs (CKELETIN_ → PROJECT_NAME_)
UPPER_NAME=$(echo "$NAME" | tr '[:lower:]-' '[:upper:]_')
sedi "s/\"CKELETIN_\"/\"${UPPER_NAME}_\"/" crates/cli/src/main.rs

# 5. Update ping message to use new name
sedi "s/ckeletin-rust is alive/$NAME is alive/g" crates/domain/src/ping.rs
sedi "s/ckeletin-rust/$NAME/g" crates/cli/tests/cli.rs

# NOTE: The `ping` command is intentionally KEPT as the worked example. The
# steps above already renamed it (domain logic, CLI handler, and both the
# human and JSON integration tests). Do NOT strip it. `ping` is the only
# subcommand; deleting it leaves an empty `Commands` enum that the entry point
# cannot match exhaustively, so the project would fail to compile — and init
# would abort before creating the git repo (see issue #1). ckeletin-go's
# scaffold keeps its demo command for the same reason. Replace or extend
# `ping` when you add your first real command — see AGENTS.md, "Adding a New
# Command". Ref: https://github.com/peiman/ckeletin-rust/issues/1

# 6. Reset CHANGELOG.md
cat > CHANGELOG.md << 'CHANGELOG'
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
CHANGELOG

# 7. Verify — compile ALL targets (lib, bin, AND tests). Checking only the
#    default targets would miss a broken integration-test file: a test that
#    fails to compile does not surface until the user's first `just check`.
echo "Verifying..."
if cargo check --workspace --all-targets -q; then
    echo "Workspace and tests compile."
else
    echo "Error: workspace does not compile after init. Something went wrong."
    exit 1
fi

# 8. Reset git history
CKELETIN_VERSION=$(cat .ckeletin/VERSION)
rm -rf .git
git init
git add -A
git commit -m "Initial scaffold from ckeletin-rust v$CKELETIN_VERSION"
git tag -a "v0.0.0" -m "Initial scaffold"

echo ""
echo "Done! $NAME is ready."
echo "  Binary: cargo run -p cli"
echo "  Tests:  just check"

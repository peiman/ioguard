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

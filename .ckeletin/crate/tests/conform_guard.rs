//! conform is upstream-only — it must no-op (not error) in a consumer repo.
//!
//! `conform` / `conform-refresh` / `conform-report` validate ckeletin-rust
//! against its own spec (CKSPEC requirements via `conformance/requirements.json`,
//! a project-owned file that lives ONLY in the framework repo). The recipes
//! propagate to consumers via `.ckeletin/`, but a consumer has no spec — so
//! `just conform` used to fail with "cannot read vendored spec" on every
//! downstream repo (found updating triz, 2026-06-05).
//!
//! The fix: the conform recipes detect a consumer (the upstream `repository`
//! slug is absent from the root Cargo.toml — `just init` rewrites it) and exit 0
//! with an explanation instead of erroring. This test asserts that contract by
//! copying the scaffold, stripping the slug (simulating a derived project), and
//! checking `just conform` no-ops cleanly. The guard short-circuits before
//! `cargo run`, so it stays fast.

use std::process::Command;

fn workspace_root() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR"); // .ckeletin/crate
    std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn conform_noops_in_a_consumer_repo() {
    if !have("just") || !have("rsync") {
        eprintln!("SKIP conform_guard: `just`/`rsync` not on PATH");
        return;
    }

    let root = workspace_root();

    // Upstream-only, like update_guard: this test simulates a consumer by copying
    // the upstream repo and stripping the slug. When it rides along inside an
    // already-init'd project (init-smoke runs the new project's full suite), the
    // slug is already gone and there's nothing to strip — skip there.
    let root_manifest =
        std::fs::read_to_string(std::path::Path::new(&root).join("Cargo.toml")).unwrap_or_default();
    if !root_manifest.contains("peiman/ckeletin-rust") {
        eprintln!("SKIP conform_guard: not the ckeletin-rust upstream repo (derived project)");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("consumer-copy");

    let status = Command::new("rsync")
        .args([
            "-a",
            "--exclude=.git",
            "--exclude=target",
            &format!("{root}/"),
            project_dir.to_str().unwrap(),
        ])
        .status()
        .expect("rsync failed");
    assert!(status.success(), "rsync copy failed");

    // Simulate a derived project: remove the upstream slug from the root
    // Cargo.toml (this is what `just init` does when scaffolding).
    let manifest = project_dir.join("Cargo.toml");
    let original = std::fs::read_to_string(&manifest).unwrap();
    let rewritten = original.replace("peiman/ckeletin-rust", "someuser/derived-project");
    assert_ne!(
        original, rewritten,
        "expected to find the upstream slug to strip"
    );
    std::fs::write(&manifest, rewritten).unwrap();

    let out = Command::new("just")
        .arg("conform")
        .current_dir(&project_dir)
        .output()
        .expect("failed to run `just conform`");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "`just conform` must no-op (exit 0) in a consumer repo, not error.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("upstream-only"),
        "`just conform` should explain it is upstream-only in a consumer repo.\nstdout: {stdout}"
    );
    // It must NOT have reached the generator (which would error on the missing spec).
    assert!(
        !stderr.contains("cannot read vendored spec"),
        "conform reached the generator instead of short-circuiting.\nstderr: {stderr}"
    );
}

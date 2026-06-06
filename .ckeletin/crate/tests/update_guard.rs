//! Framework-update self-guard test.
//!
//! `just ckeletin-update`, `ckeletin-update-dry-run`, and
//! `ckeletin-update-check-compatibility` must refuse to run against the
//! ckeletin-rust *upstream* repo itself — pulling the framework into the repo
//! that produces it is meaningless (it would add a `ckeletin-upstream` remote
//! pointing at itself and re-checkout its own `.ckeletin/`). This mirrors
//! ckeletin-go's `task ckeletin:update` guard, which compares the go.mod module
//! path to the upstream module. The Rust analog is the CLI crate name: `just
//! init` renames `crates/cli/Cargo.toml`'s `name` away from `ckeletin-rust`, so
//! a still-named `ckeletin-rust` CLI crate is the upstream-repo fingerprint.
//!
//! The harness copies the scaffold to a temp dir WITHOUT `.git` and runs the
//! recipes there. The guard short-circuits before any git command, so a guarded
//! recipe exits 0 with the upstream message; an unguarded one would fall through
//! to `git …` and fail. The check is therefore hermetic — no network, no remote
//! mutation of the real repo — and fast (no cargo build is reached).

use std::process::Command;

/// Workspace root (parent of `.ckeletin/crate/`).
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
fn update_recipes_refuse_to_run_on_upstream_repo() {
    // These recipes are `just`-driven; the canonical test entry (`just check`)
    // and CI both have `just` installed. Skip visibly under a bare `cargo test`
    // on a machine without it rather than reporting a false failure.
    if !have("just") || !have("rsync") {
        eprintln!("SKIP update_guard: `just`/`rsync` not on PATH");
        return;
    }

    let root = workspace_root();

    // Upstream-only, like init_smoke: the guard fires on the `peiman/ckeletin-rust`
    // slug, which `just init` rewrites in derived projects. When this test rides
    // along inside an init'd project (e.g. the init-smoke harness runs the new
    // project's full suite), the slug is gone, so the guard would NOT fire and the
    // assertions below would not hold. Skip rather than fail in that context.
    let root_manifest =
        std::fs::read_to_string(std::path::Path::new(&root).join("Cargo.toml")).unwrap_or_default();
    if !root_manifest.contains("peiman/ckeletin-rust") {
        eprintln!("SKIP update_guard: not the ckeletin-rust upstream repo (derived project)");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("upstream-copy");

    // Copy the scaffold WITHOUT .git (so the guard, which runs before any git
    // command, is the only thing that can let the recipe succeed) and without
    // target (speed).
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

    // The copy keeps the upstream CLI crate name, so every update recipe must
    // detect "this is upstream" and bail cleanly.
    for recipe in [
        "ckeletin-update",
        "ckeletin-update-dry-run",
        "ckeletin-update-check-compatibility",
    ] {
        let out = Command::new("just")
            .arg(recipe)
            .current_dir(&project_dir)
            .output()
            .unwrap_or_else(|e| panic!("failed to run `just {recipe}`: {e}"));

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(
            out.status.success(),
            "`just {recipe}` should exit 0 on the upstream repo (guard short-circuit), \
             but it failed.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("upstream repository itself"),
            "`just {recipe}` should print the upstream-guard message.\nstdout: {stdout}\nstderr: {stderr}"
        );
        // The guard must fire BEFORE touching git remotes — there is no .git in
        // the copy, so any git fallthrough would have surfaced in stderr.
        assert!(
            !stderr.contains("not a git repository") && !stderr.contains("fatal:"),
            "`just {recipe}` reached a git command instead of short-circuiting.\nstderr: {stderr}"
        );
    }
}

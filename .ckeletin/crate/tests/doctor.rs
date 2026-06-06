//! `ckeletin-doctor` smoke test.
//!
//! The doctor is an environment diagnostic: it reports the framework version and
//! the toolchain + tools the framework depends on. It is INFORMATIONAL — it must
//! exit 0 even when a tool is missing (it reports status, it does not gate the
//! build), so it is deliberately NOT part of `just check`. This test asserts it
//! runs and surfaces the key sections. Unlike the update self-guard, the doctor
//! is not upstream-specific, so it also runs cleanly inside an init'd project.

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
fn doctor_reports_environment_and_never_fails() {
    if !have("just") {
        eprintln!("SKIP doctor: `just` not on PATH");
        return;
    }

    let out = Command::new("just")
        .arg("ckeletin-doctor")
        .current_dir(workspace_root())
        .output()
        .expect("failed to run `just ckeletin-doctor`");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "ckeletin-doctor is informational and must exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Key sections the doctor must surface.
    for expect in [
        "ckeletin framework v",
        "Toolchain",
        "Tools",
        "cargo-deny",
        "just",
    ] {
        assert!(
            stdout.contains(expect),
            "doctor output missing {expect:?}.\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}

#[test]
fn doctor_json_is_machine_readable() {
    // For autonomous operation (workhorse driving ckeletin), `ckeletin-doctor
    // json` must emit a single valid JSON object an agent can parse — framework
    // version, toolchain, and tool presence as booleans.
    if !have("just") {
        eprintln!("SKIP doctor json: `just` not on PATH");
        return;
    }

    let out = Command::new("just")
        .args(["ckeletin-doctor", "json"])
        .current_dir(workspace_root())
        .output()
        .expect("failed to run `just ckeletin-doctor json`");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "doctor json must exit 0.\nstdout: {stdout}"
    );

    // Must be exactly one valid JSON object.
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("doctor json is not valid JSON: {e}\nstdout: {stdout}"));

    assert!(
        v.get("framework_version")
            .and_then(|x| x.as_str())
            .is_some(),
        "json missing framework_version: {v}"
    );
    assert!(
        v.pointer("/toolchain/pinned")
            .and_then(|x| x.as_str())
            .is_some(),
        "json missing toolchain.pinned: {v}"
    );
    // tool presence must be booleans an agent can branch on.
    assert!(
        v.pointer("/tools/cargo-deny")
            .and_then(|x| x.as_bool())
            .is_some(),
        "json missing boolean tools.cargo-deny: {v}"
    );
}

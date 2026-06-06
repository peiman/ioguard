//! Framework purity tests — verify no project-specific values leak into
//! the framework crate. If any test here fails, a hardcoded value has
//! crept into framework code that will be wrong for every project
//! except the scaffold itself.
//!
//! These tests read actual source files and check their contents.
//! They are invariant tests — they verify properties of the codebase,
//! not behavior of the code.

use std::fs;
use std::path::Path;

/// The framework source directory.
fn framework_src() -> &'static Path {
    // Tests run from the crate root, which is .ckeletin/crate/
    Path::new("src")
}

/// Read all .rs files in the framework source directory.
fn all_framework_source() -> Vec<(String, String)> {
    let src = framework_src();
    if !src.exists() {
        // Running from workspace root — adjust path
        let alt = Path::new(".ckeletin/crate/src");
        if alt.exists() {
            return read_rs_files(alt);
        }
        panic!("Cannot find framework source directory");
    }
    read_rs_files(src)
}

fn read_rs_files(dir: &Path) -> Vec<(String, String)> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
        .map(|e| {
            let path = e.path().display().to_string();
            let content = fs::read_to_string(e.path()).unwrap();
            (path, content)
        })
        .collect()
}

#[test]
fn no_project_name_in_framework_source() {
    let forbidden = ["ckeletin-rust", "workhorse"];
    let files = all_framework_source();
    assert!(!files.is_empty(), "Should find framework source files");

    for (path, content) in &files {
        // Skip test modules inside source files
        let code = if let Some(pos) = content.find("#[cfg(test)]") {
            &content[..pos]
        } else {
            content.as_str()
        };

        for name in &forbidden {
            assert!(
                !code.contains(name),
                "Framework file {path} contains project-specific string \"{name}\". \
                 Framework code must be generic — project-specific values belong \
                 in the project's cli/main.rs or config, not in .ckeletin/crate/."
            );
        }
    }
}

#[test]
fn no_hardcoded_env_prefix_in_framework_source() {
    let files = all_framework_source();

    for (path, content) in &files {
        let code = if let Some(pos) = content.find("#[cfg(test)]") {
            &content[..pos]
        } else {
            content.as_str()
        };

        // The framework should never hardcode an env prefix in executable code.
        // Config::load() accepts it as a parameter. Doc comments (///) are OK.
        let executable_lines: Vec<&str> = code
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.starts_with("///") && !trimmed.starts_with("//")
            })
            .collect();
        let executable_code = executable_lines.join("\n");
        assert!(
            !executable_code.contains("CKELETIN_") && !executable_code.contains("WORKHORSE_"),
            "Framework file {path} contains hardcoded env prefix in executable code. \
             The prefix must be passed as a parameter to Config::load(), \
             not hardcoded in framework source."
        );
    }
}

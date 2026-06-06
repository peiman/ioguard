fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = std::path::Path::new(&crate_dir)
        .parent() // crates/
        .unwrap()
        .parent() // workspace root
        .unwrap();
    let output_dir = workspace_root.join("include");
    std::fs::create_dir_all(&output_dir).unwrap();
    let output_file = output_dir.join("ioguard.h");

    let config =
        cbindgen::Config::from_file(std::path::Path::new(&crate_dir).join("cbindgen.toml"))
            .expect("failed to read cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen failed to generate bindings")
        .write_to_file(&output_file);

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}

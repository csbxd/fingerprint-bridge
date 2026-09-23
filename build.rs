use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    for path in ["scripts/prepare_char2.py", "native/char2_provider.c"] {
        println!("cargo:rerun-if-changed={path}");
    }
    for variable in ["CC", "AR", "NM", "OBJCOPY", "CFLAGS"] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    if env::var_os("CARGO_FEATURE_PATCHED_TLS").is_none() {
        return;
    }
    assert_eq!(
        env::var("HOST").unwrap(),
        env::var("TARGET").unwrap(),
        "char2 provider currently requires a native build, not cross compilation"
    );
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("char2");
    let status = Command::new("python3")
        .arg(root.join("scripts/prepare_char2.py"))
        .arg("--output")
        .arg(&output)
        .current_dir(&root)
        .status()
        .expect("start pinned char2 provider build");
    assert!(status.success(), "char2 provider build failed closed");
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=bridge_char2_provider");
    println!("cargo:rustc-link-lib=static=bridge_char2_crypto");
    println!("cargo:rustc-link-lib=pthread");
}

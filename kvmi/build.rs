use std::env;
use std::fs;
use std::io::Result;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-Iinclude")
        .derive_default(true)
        .derive_partialeq(true)
        // TODO: need to switch this to
        // .rustified_non_exhaustive_enum(".*")
        // when it is available
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't writing bindings");

    println!("cargo:rerun-if-changed=wrapper.h");
    print_dir(Path::new("include"))
}

fn print_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                print_dir(&path)?;
            } else {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    Ok(())
}

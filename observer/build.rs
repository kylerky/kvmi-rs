use std::path::Path;

fn main() {
    let schema_path = Path::new("schema/kvmi.capnp");
    let mut prefix = schema_path.ancestors().skip(1);
    let prefix = prefix.next().unwrap();
    capnpc::CompilerCommand::new()
        .file(schema_path)
        .src_prefix(prefix)
        .run()
        .expect("failed to compile capnp schema.");
    println!("cargo:rerun-if-changed={}", schema_path.display());
}

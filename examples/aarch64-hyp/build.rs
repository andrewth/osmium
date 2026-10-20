use std::env;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo::rustc-link-arg=-T{dir}/link.x");
    println!("cargo::rerun-if-changed=link.x");
}

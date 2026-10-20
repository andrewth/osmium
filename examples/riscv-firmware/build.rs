fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    println!("cargo::rustc-link-arg=-T{dir}/link.x");
    println!("cargo::rerun-if-changed=link.x");
}

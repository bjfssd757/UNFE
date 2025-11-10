fn main() {
    cc::Build::new()
        .file("C/unfe.c")
        .compile("unfe");

    println!("cargo:rerun-if-changed=C/unfe.c");
}
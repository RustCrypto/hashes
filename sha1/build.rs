extern crate cc;

fn main() {
    let asm_path = if cfg!(target_arch = "x86") {
        "src/x86.S"
    } else if cfg!(target_arch = "x86_64") {
        "src/x64.S"
    } else if cfg!(target_arch = "aarch64") {
        "src/aarch64.S"
    } else {
        panic!("Unsupported target architecture");
    };
    let mut build = cc::Build::new();
    if cfg!(target_arch = "aarch64") {
        build.flag("-march=armv8-a+crypto");
    }
    build.flag("-c")
        .file(asm_path)
        .compile("libsha1.a");
}

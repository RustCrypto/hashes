extern crate cc;

fn main() {
    let asm_path = if cfg!(target_arch = "x86") {
        "src/x86.S"
    } else if cfg!(target_arch = "x86_64") {
        "src/x64.S"
    } else {
        panic!("Unsupported target architecture");
    };
    cc::Build::new()
              .flag("-c")
              .file(asm_path)
              .compile("libmd5.a");
}

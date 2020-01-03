extern crate cc;

fn main() {
    let mut build256 = cc::Build::new();
    let (sha256_path, sha512_path) = if cfg!(target_arch = "x86") {
        ("src/sha256_x86.S", "src/sha512_x86.S")
    } else if cfg!(target_arch = "x86_64") {
        ("src/sha256_x64.S", "src/sha512_x64.S")
    } else if cfg!(target_arch = "aarch64") {
        build256.flag("-march=armv8-a+crypto");
        ("src/sha256_aarch64.S", "")
    } else {
        panic!("Unsupported target architecture");
    };
    if !cfg!(target_arch = "aarch64") {
        cc::Build::new()
                  .flag("-c")
                  .file(sha512_path)
                  .compile("libsha512.a");
    }
    build256
              .flag("-c")
              .file(sha256_path)
              .compile("libsha256.a");
}

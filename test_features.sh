cd md5 && cargo test --features asm && cd .. &&
cd sha1 && cargo test --features asm && cd .. &&
cd whirlpool && cargo test --features asm && cd .. &&
cd blake2 && cargo test --features simd &&
             cargo test --features simd_opt &&
             cargo test --features simd_asm &&
             RUSTFLAGS="-Ctarget-cpu=native" cargo test --features coresimd &&
             RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=-ssse3" cargo test --features coresimd &&
             RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=-avx2" cargo test --features coresimd

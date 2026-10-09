#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
compile_error!("riscv-zknh backend can be used only on riscv32 and riscv64 target arches");

cfg_if::cfg_if! {
    if #[cfg(sha2_backend_riscv_zknh = "compact")] {
        mod compact;
        use compact::compress_block;
    } else {
        mod unroll;
        use unroll::compress_block;
    }
}

#[target_feature(enable = "zknh")]
pub(super) fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    for block in blocks.iter().map(load_block) {
        compress_block(state, block);
    }
}

fn load_block(block: &[u8; 128]) -> [u64; 16] {
    let (chunks, tail) = block.as_chunks();
    assert!(tail.is_empty());
    core::array::from_fn(|i| u64::from_be_bytes(chunks[i]))
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "riscv64")] {
        use core::arch::riscv64::{sha512sig0, sha512sig1, sha512sum0, sha512sum1};
    } else {
        use core::arch::riscv32::{
            sha512sig0h, sha512sig0l, sha512sig1h, sha512sig1l, sha512sum0r, sha512sum1r,
        };

        #[target_feature(enable = "zknh")]
        fn sha512sum0(x: u64) -> u64 {
            let a = sha512sum0r((x >> 32) as u32, x as u32);
            let b = sha512sum0r(x as u32, (x >> 32) as u32);
            ((a as u64) << 32) | (b as u64)
        }

        #[target_feature(enable = "zknh")]
        fn sha512sum1(x: u64) -> u64 {
            let a = sha512sum1r((x >> 32) as u32, x as u32);
            let b = sha512sum1r(x as u32, (x >> 32) as u32);
            ((a as u64) << 32) | (b as u64)
        }

        #[target_feature(enable = "zknh")]
        fn sha512sig0(x: u64) -> u64 {
            let a = sha512sig0h((x >> 32) as u32, x as u32);
            let b = sha512sig0l(x as u32, (x >> 32) as u32);
            ((a as u64) << 32) | (b as u64)
        }

        #[target_feature(enable = "zknh")]
        fn sha512sig1(x: u64) -> u64 {
            let a = sha512sig1h((x >> 32) as u32, x as u32);
            let b = sha512sig1l(x as u32, (x >> 32) as u32);
            ((a as u64) << 32) | (b as u64)
        }
    }
}

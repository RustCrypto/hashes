#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
compile_error!("riscv-zknh backend can be used only on riscv32 and riscv64 target arches");

#[cfg(target_arch = "riscv32")]
use core::arch::riscv32::{sha256sig0, sha256sig1, sha256sum0, sha256sum1};
#[cfg(target_arch = "riscv64")]
use core::arch::riscv64::{sha256sig0, sha256sig1, sha256sum0, sha256sum1};

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
pub(super) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks {
        let block: [u32; 16] = core::array::from_fn(|i| {
            let chunk = block[4 * i..][..4].try_into().unwrap();
            u32::from_be_bytes(chunk)
        });
        compress_block(state, block);
    }
}

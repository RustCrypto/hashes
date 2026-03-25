#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
compile_error!("riscv-zknh backend can be used only on riscv32 and riscv64 target arches");

mod utils;

cfg_if::cfg_if! {
    if #[cfg(sha2_backend_riscv_zknh = "compact")] {
        mod compact;
        pub(super) use compact::compress;
    } else {
        mod unroll;
        pub(super) use unroll::compress;
    }
}

#[cfg(target_arch = "riscv64")]
use core::arch::riscv64::{sha512sig0, sha512sig1, sha512sum0, sha512sum1};

#[cfg(target_arch = "riscv32")]
use core::arch::riscv32::*;

#[cfg(target_arch = "riscv32")]
#[target_feature(enable = "zknh")]
fn sha512sum0(x: u64) -> u64 {
    let a = sha512sum0r((x >> 32) as u32, x as u32);
    let b = sha512sum0r(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
#[target_feature(enable = "zknh")]
fn sha512sum1(x: u64) -> u64 {
    let a = sha512sum1r((x >> 32) as u32, x as u32);
    let b = sha512sum1r(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
#[target_feature(enable = "zknh")]
fn sha512sig0(x: u64) -> u64 {
    let a = sha512sig0h((x >> 32) as u32, x as u32);
    let b = sha512sig0l(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
#[target_feature(enable = "zknh")]
fn sha512sig1(x: u64) -> u64 {
    let a = sha512sig1h((x >> 32) as u32, x as u32);
    let b = sha512sig1l(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

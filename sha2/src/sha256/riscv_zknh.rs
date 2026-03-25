#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
compile_error!("riscv-zknh backend can be used only on riscv32 and riscv64 target arches");

mod utils;

#[cfg(target_arch = "riscv32")]
use core::arch::riscv32::{sha256sig0, sha256sig1, sha256sum0, sha256sum1};
#[cfg(target_arch = "riscv64")]
use core::arch::riscv64::{sha256sig0, sha256sig1, sha256sum0, sha256sum1};

cfg_if::cfg_if! {
    if #[cfg(sha2_backend_riscv_zknh = "compact")] {
        mod compact;
        pub(super) use compact::compress;
    } else {
        mod unroll;
        pub(super) use unroll::compress;
    }
}

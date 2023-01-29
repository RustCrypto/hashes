// TODO (laudiacay): here, do the switch to figure out which architecture's method we'll do...
// here's how that md5 PR did it (obviously wrong for what we want here...)
// #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
// mod x86;
//
// #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
// pub use x86::compress;

#[cfg(all(feature = "inline-asm", target_arch = "x86",))]
mod x86;
#[cfg(all(feature = "inline-asm", target_arch = "x86",))]
pub use x86::compress;

#[cfg(all(feature = "inline-asm", target_arch = "x86_64",))]
mod x86_64;
#[cfg(all(feature = "inline-asm", target_arch = "x86_64",))]
pub use x86_64::compress;

#[cfg(all(feature = "inline-asm", target_arch = "aarch64",))]
mod aarch64;
#[cfg(all(feature = "inline-asm", target_arch = "aarch64",))]
pub use aarch64::compress;

// TODO(laudiacay) i don't know how to detect M1
mod aarch64_apple;

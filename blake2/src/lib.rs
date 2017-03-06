#![no_std]
#![cfg_attr(feature = "simd", feature(platform_intrinsics, repr_simd))]
#![cfg_attr(feature = "simd_opt", feature(cfg_target_feature))]
#![cfg_attr(feature = "simd_asm", feature(asm))]

extern crate byte_tools;
extern crate digest;
// extern crate crypto_mac;
//extern crate crypto_ops;
extern crate generic_array;

mod consts;
mod as_bytes;
mod bytes;

mod simdty;
mod simdint;
mod simdop;
mod simd_opt;
mod simd;


#[macro_use]
mod blake2;

mod blake2b;
mod blake2s;

pub use digest::Digest;
pub use blake2b::Blake2b;
pub use blake2s::Blake2s;

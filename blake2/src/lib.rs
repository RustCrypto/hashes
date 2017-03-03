#![no_std]
extern crate byte_tools;
extern crate digest;
// extern crate crypto_mac;
extern crate crypto_ops;
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

pub use digest::Digest;

use generic_array::{GenericArray, ArrayLength};
use core::marker::PhantomData;
use core::cmp;
use consts::BLAKE2B_KEYBYTES;
use byte_tools::copy_memory;
use generic_array::typenum::U64;

blake2_impl!(Blake2b, u64, u64x4,
    64, 32, 24, 16, 63,
    consts::BLAKE2B_IV);

pub type Blake2b512 = Blake2b<U64>;

//blake2_impl!(Blake2s, u32, u32x4, 32, 16, 12, 8, 7,
//    consts::BLAKE2S_IV;
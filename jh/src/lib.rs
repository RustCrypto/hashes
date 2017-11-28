// copyright 2017 Kaz Wesley

//! Optimized implementation of JH for x86-64 systems.

#![no_std]
#![feature(repr_align, attr_literals)]
#![cfg(target_arch = "x86_64")]

pub extern crate digest;

pub use digest::Digest;

use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{U28, U32, U48, U64};

mod consts;

#[derive(Clone)]
#[repr(C, align(128))]
struct State {
    hashbitlen: usize,
    databitlen: u64,
    datasize_in_buffer: u64,
    _pad0: u64,
    x: [u8; 128],
    buffer: [u8; 64],
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("State")
            .field("hashbitlen", &self.hashbitlen)
            .field("databitlen", &self.databitlen)
            .field("datasize_in_buffer", &self.datasize_in_buffer)
            .field("x", &"(array)")
            .field("buffer", &"(array)")
            .finish()
    }
}

extern "C" {
    fn jh_update(state: *mut State, data: *const u8, databitlen: u64);
    fn jh_final(state: *mut State);
}

macro_rules! define_hasher {
    ($name:ident, $init:path, $size:expr, $OutputBytes:ty) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            state: State,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    state: State {
                        hashbitlen: $size,
                        databitlen: 0,
                        datasize_in_buffer: 0,
                        _pad0: 0,
                        x: *$init,
                        buffer: [0u8; 64],
                    },
                }
            }
        }

        impl digest::BlockInput for $name {
            type BlockSize = U64;
        }

        impl digest::Input for $name {
            fn process(&mut self, data: &[u8]) {
                unsafe {
                    jh_update(&mut self.state, data.as_ptr(), data.len() as u64 * 8);
                }
            }
        }

        impl digest::FixedOutput for $name {
            type OutputSize = $OutputBytes;

            fn fixed_result(mut self) -> GenericArray<u8, $OutputBytes> {
                unsafe {
                    jh_final(&mut self.state);
                }
                let mut out = GenericArray::default();
                out.copy_from_slice(&self.state.x[(128 - ($size/8))..128]);
                out
            }
        }
    }
}

define_hasher!(Jh224, consts::JH224_H0, 224, U28);
define_hasher!(Jh256, consts::JH256_H0, 256, U32);
define_hasher!(Jh384, consts::JH384_H0, 384, U48);
define_hasher!(Jh512, consts::JH512_H0, 512, U64);

#[cfg(test)]
mod tests {}

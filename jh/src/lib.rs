// copyright 2017 Kaz Wesley

//! Optimized implementation of JH for x86-64 systems.

#![no_std]
#![cfg(target_arch = "x86_64")]

pub extern crate digest;

pub use digest::Digest;

use block_buffer::BlockBuffer512;
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{U28, U32, U48, U64, Unsigned};

mod consts;

#[derive(Clone)]
#[repr(C, align(128))]
struct State([u8; 128]);

extern "C" {
    fn f8(state: *mut State, block: *const [u8; 64]);
}

impl State {
    fn process_block(&mut self, block: &[u8; 64]) {
        unsafe { f8(self, block) };
    }
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_tuple("State")
            .field(&"(array)")
            .finish()
    }
}

struct DigestPadToEnd {}
impl block_buffer::Padding for DigestPadToEnd {
    fn pad(block: &mut [u8], pos: usize) {
        block[pos] = 0x80;
        if pos+1 < block.len() {
            for x in &mut block[pos+1..] { *x = 0 };
        }
    }
}

macro_rules! define_hasher {
    ($name:ident, $init:path, $OutputBytes:ident) => {
        #[derive(Clone)]
        pub struct $name {
            state: State,
            buffer: BlockBuffer512,
            datalen: usize,
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                f.debug_struct("Jh")
                    .field("state", &self.state)
                    .field("buffer", &"(BlockBuffer512)")
                    .field("datalen", &self.datalen)
                    .finish()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    state: State(*$init),
                    buffer: BlockBuffer512::default(),
                    datalen: 0
                }
            }
        }

        impl digest::BlockInput for $name {
            type BlockSize = U64;
        }

        impl digest::Input for $name {
            fn process(&mut self, data: &[u8]) {
                self.datalen += data.len();
                let state = &mut self.state;
                self.buffer.input(data, |b| state.process_block(b))
            }
        }

        impl digest::FixedOutput for $name {
            type OutputSize = $OutputBytes;

            fn fixed_result(mut self) -> GenericArray<u8, $OutputBytes> {
                let state = &mut self.state;
                let buffer = &mut self.buffer;
                let len = self.datalen as u64 * 8;
                if buffer.position() == 0 {
                    buffer.len_padding(len.to_be(), |b| state.process_block(b));
                } else {
                    state.process_block(buffer.pad_with::<DigestPadToEnd>());
                    let mut last = [0u8; 64];
                    last[56] = (len >> 56) as u8;
                    last[57] = (len >> 48) as u8;
                    last[58] = (len >> 40) as u8;
                    last[59] = (len >> 32) as u8;
                    last[60] = (len >> 24) as u8;
                    last[61] = (len >> 16) as u8;
                    last[62] = (len >> 8) as u8;
                    last[63] = len as u8;
                    state.process_block(&last);
                }
                let mut out = GenericArray::default();
                out.copy_from_slice(&state.0[(128 - $OutputBytes::to_usize())..]);
                out
            }
        }
    }
}

define_hasher!(Jh224, consts::JH224_H0, U28);
define_hasher!(Jh256, consts::JH256_H0, U32);
define_hasher!(Jh384, consts::JH384_H0, U48);
define_hasher!(Jh512, consts::JH512_H0, U64);

#[cfg(test)]
mod tests {}

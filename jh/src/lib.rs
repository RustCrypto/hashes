// copyright 2017 Kaz Wesley

//! Optimized implementation of JH for x86-64 systems.

#![no_std]
#![cfg(target_arch = "x86_64")]

pub extern crate digest;

pub use digest::Digest;

use block_buffer::byteorder::BigEndian;
use block_buffer::BlockBuffer;
use block_buffer::generic_array::GenericArray as BBGenericArray;
use digest::generic_array::GenericArray as DGenericArray;
use digest::generic_array::typenum::{U28, U32, U48, U64, Unsigned};

mod consts;

#[derive(Clone)]
#[repr(C, align(128))]
struct State([u8; 128]);

extern "C" {
    fn f8(state: *mut State, block: *const [u8; 64]);
}

impl State {
    fn process_block(&mut self, block: &BBGenericArray<u8, U64>) {
        unsafe { f8(self, block.as_slice().as_ptr() as *const [u8; 64]) };
    }
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_tuple("State")
            .field(&"(array)")
            .finish()
    }
}

macro_rules! define_hasher {
    ($name:ident, $init:path, $OutputBytes:ident) => {
        #[derive(Clone)]
        pub struct $name {
            state: State,
            buffer: BlockBuffer<U64>,
            datalen: usize,
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                f.debug_struct("Jh")
                    .field("state", &self.state)
                    .field("buffer", &"(BlockBuffer<U64>)")
                    .field("datalen", &self.datalen)
                    .finish()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    state: State(*$init),
                    buffer: BlockBuffer::default(),
                    datalen: 0
                }
            }
        }

        impl digest::BlockInput for $name {
            type BlockSize = U64;
        }

        impl digest::Input for $name {
            fn input<T: AsRef<[u8]>>(&mut self, data: T) {
                let data = data.as_ref();
                self.datalen += data.len();
                let state = &mut self.state;
                self.buffer.input(data, |b| state.process_block(b))
            }
        }

        impl digest::FixedOutput for $name {
            type OutputSize = $OutputBytes;

            fn fixed_result(mut self) -> DGenericArray<u8, $OutputBytes> {
                let state = &mut self.state;
                let buffer = &mut self.buffer;
                let len = self.datalen as u64 * 8;
                if buffer.position() == 0 {
                    buffer.len64_padding::<BigEndian, _>(len, |b| state.process_block(b));
                } else {
                    use block_buffer::block_padding::Iso7816;
                    state.process_block(buffer.pad_with::<Iso7816>().unwrap());
                    let mut last = BBGenericArray::default();
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
                let mut out = DGenericArray::default();
                out.copy_from_slice(&state.0[(128 - $OutputBytes::to_usize())..]);
                out
            }
        }

        impl digest::Reset for $name {
            fn reset(&mut self) {
                *self = Self::default();
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

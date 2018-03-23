// copyright 2017 Kaz Wesley

#![no_std]

extern crate block_buffer;
extern crate block_padding;
extern crate byte_tools;
extern crate threefish;
pub extern crate digest;

pub use digest::generic_array::GenericArray;
pub use digest::Digest;

use block_buffer::{BlockBuffer1024, BlockBuffer256, BlockBuffer512};
use block_padding::ZeroPadding;
use byte_tools::{write_u64_le, write_u64v_le};
use core::mem;
use digest::generic_array::ArrayLength;
use digest::generic_array::typenum::{NonZero, Unsigned};
use threefish::{BlockCipher, Threefish1024, Threefish256, Threefish512};

#[repr(C)]
#[derive(Clone)]
struct State<X> {
    t: [u64; 2],
    x: X,
}

impl<X> core::fmt::Debug for State<X> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("State<X>")
            .field("t", &"(unknown)")
            .field("x", &"(unknown)")
            .finish()
    }
}

const VERSION: u64 = 1;
const ID_STRING_LE: u64 = 0x33414853;
const SCHEMA_VER: u64 = (VERSION << 32) | ID_STRING_LE;
const CFG_TREE_INFO_SEQUENTIAL: u64 = 0;
const T1_FLAG_FIRST: u64 = 1 << 62;
const T1_FLAG_FINAL: u64 = 1 << 63;
const T1_BLK_TYPE_CFG: u64 = 4 << 56;
const T1_BLK_TYPE_MSG: u64 = 48 << 56;
const T1_BLK_TYPE_OUT: u64 = 63 << 56;
const CFG_STR_LEN: usize = 4 * 8;

macro_rules! define_hasher {
    ($name:ident, $buffer:ty, $threefish:ident, $state_bits:expr) => {
        #[derive(Clone)]
        pub struct $name<N: Unsigned+ArrayLength<u8>+NonZero> {
            state: State<[u64; ($state_bits/64)]>,
            buffer: $buffer,
            _output: core::marker::PhantomData<GenericArray<u8, N>>
        }

        impl<N> core::fmt::Debug for $name<N> where N: Unsigned+ArrayLength<u8>+NonZero {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                f.debug_struct("Skein")
                    .field("state", &self.state)
                    .field("buffer.position()", &self.buffer.position())
                    .finish()
            }
        }

        impl<N> $name<N> where N: Unsigned+ArrayLength<u8>+NonZero {
            fn process_block(state: &mut State<[u64; ($state_bits/64)]>,
                             block: &[u8; $state_bits/8], byte_count_add: usize) {
                state.t[0] += byte_count_add as u64;
                let fish = $threefish::with_tweak(unsafe { mem::transmute(&state.x) },
                                                  unsafe { mem::transmute(&state.t) });
                let mut x = block.clone();
                fish.encrypt_block(unsafe { mem::transmute(&mut x) });
                let bkb: &[u64; $state_bits/64] = unsafe { mem::transmute(&x) };
                let bkc: &[u64; $state_bits/64] = unsafe { mem::transmute(block) };
                for (a, (b, c)) in state.x.iter_mut().zip(bkb.iter().zip(bkc)) { *a = *b ^ *c; }
                state.t[1] &= !T1_FLAG_FIRST;
            }
        }

        impl<N> Default for $name<N> where N: Unsigned+ArrayLength<u8>+NonZero {
            fn default() -> Self {
                // build and process config block
                let mut state = State {
                    t: [0, T1_FLAG_FIRST | T1_BLK_TYPE_CFG | T1_FLAG_FINAL],
                    x: [0u64; ($state_bits/64)],
                };
                let mut cfg = [0u8; $state_bits/8];
                write_u64v_le(&mut cfg[..24], &[SCHEMA_VER, N::to_u64() * 8, CFG_TREE_INFO_SEQUENTIAL]);
                Self::process_block(&mut state, &cfg, CFG_STR_LEN);

                // The chaining vars ctx->X are now initialized for the given hashBitLen.
                // Set up to process the data message portion of the hash (default)
                state.t = [0, T1_FLAG_FIRST | T1_BLK_TYPE_MSG];
                Self {
                    state,
                    buffer: Default::default(),
                    _output: Default::default()
                }
            }
        }

        impl<N> digest::BlockInput for $name<N> where N: Unsigned+ArrayLength<u8>+NonZero  {
            type BlockSize = <$threefish as BlockCipher>::BlockSize;
        }

        impl<N> digest::Input for $name<N> where N: Unsigned+ArrayLength<u8>+NonZero  {
            fn process(&mut self, data: &[u8]) {
                let buffer = &mut self.buffer;
                let state = &mut self.state;
                buffer.input_lazy(data, |block| Self::process_block(state, block, $state_bits/8));
            }
        }

        impl<N> digest::FixedOutput for $name<N> where N: Unsigned+ArrayLength<u8>+NonZero  {
            type OutputSize = N;

            fn fixed_result(mut self) -> GenericArray<u8, N> {
                self.state.t[1] |= T1_FLAG_FINAL;
                let pos = self.buffer.position();
                let final_block = self.buffer.pad_with::<ZeroPadding>().unwrap();
                Self::process_block(&mut self.state, final_block, pos);

                // run Threefish in "counter mode" to generate output
                let mut output = GenericArray::default();
                for (i, chunk) in output.chunks_mut($state_bits / 8).enumerate() {
                    let mut ctr = State {
                        t: [0, T1_FLAG_FIRST | T1_BLK_TYPE_OUT | T1_FLAG_FINAL],
                        x: self.state.x,
                    };
                    let mut b = [0u8; $state_bits / 8];
                    write_u64_le(&mut b[..8], i as u64);
                    Self::process_block(&mut ctr, &b, 8);
                    let n = chunk.len() / 8;
                    write_u64v_le(chunk, &ctr.x[..n]);
                }
                output
            }
        }
    }
}

#[cfg_attr(rustfmt, skip)]
define_hasher!(Skein256, BlockBuffer256, Threefish256, 256);
#[cfg_attr(rustfmt, skip)]
define_hasher!(Skein512, BlockBuffer512, Threefish512, 512);
#[cfg_attr(rustfmt, skip)]
define_hasher!(Skein1024, BlockBuffer1024, Threefish1024, 1024);

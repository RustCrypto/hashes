// copyright 2017 Kaz Wesley

//! Classic Blake in a Rustic setting

#![no_std]

extern crate block_buffer;
pub extern crate digest;

mod consts;

use block_buffer::BlockBuffer;
use core::mem;
use digest::generic_array::GenericArray;
pub use digest::Digest;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct State<T> {
    h: [T; 8],
    s: [T; 4],
    t: [T; 2],
    nullt: bool,
}

macro_rules! define_compressor {
    ($compressor:ident, $word:ident, $Bufsz:ty, $deserializer:path, $uval:expr,
     $rounds:expr, $shift0:expr, $shift1:expr, $shift2: expr, $shift3: expr) => {
        #[derive(Clone, Copy, Debug)]
        struct $compressor {
            state: State<$word>,
        }

        impl $compressor {
            fn increase_count(&mut self, count: $word) {
                let (new_t0, carry) = self.state.t[0].overflowing_add(count * 8);
                self.state.t[0] = new_t0;
                if carry { self.state.t[1] += 1; }
            }

            fn put_block(&mut self, block: &GenericArray<u8, $Bufsz>) {
                const U: [$word; 16] = $uval;

                #[inline(always)]
                fn g(v: &mut [$word; 16], m: &[$word; 16], sigma: &[u8; 16],
                    a: usize, b: usize, c: usize, d: usize, e: usize) {
                    v[a] = v[a].wrapping_add(m[sigma[e] as usize] ^ U[sigma[e+1] as usize])
                        .wrapping_add(v[b]);
                    v[d] = (v[d] ^ v[a]).rotate_right($shift0);
                    v[c] = v[c].wrapping_add(v[d]);
                    v[b] = (v[b] ^ v[c]).rotate_right($shift1);
                    v[a] = v[a].wrapping_add(m[sigma[e+1] as usize] ^ U[sigma[e] as usize])
                        .wrapping_add(v[b]);
                    v[d] = (v[d] ^ v[a]).rotate_right($shift2);
                    v[c] = v[c].wrapping_add(v[d]);
                    v[b] = (v[b] ^ v[c]).rotate_right($shift3);
                }

                let mut m = [0; 16];
                for (mx, b) in m.iter_mut().zip(block.chunks(mem::size_of::<$word>())) {
                    *mx = $deserializer(b);
                }

                let mut v = [0; 16];
                &v[..8].copy_from_slice(&self.state.h);
                &v[8..].copy_from_slice(&U[..8]);
                for (vx, sx) in v[8..11].iter_mut().zip(&self.state.s) {
                    *vx ^= *sx;
                }

                // don't xor t when the block is only padding
                if !self.state.nullt {
                    v[12] ^= self.state.t[0];
                    v[13] ^= self.state.t[0];
                    v[14] ^= self.state.t[1];
                    v[15] ^= self.state.t[1];
                }

                for sigma in &SIGMA[..$rounds] {
                    // column step
                    g(&mut v, &m, sigma, 0,  4,  8, 12,  0 );
                    g(&mut v, &m, sigma, 1,  5,  9, 13,  2 );
                    g(&mut v, &m, sigma, 2,  6, 10, 14,  4 );
                    g(&mut v, &m, sigma, 3,  7, 11, 15,  6 );
                    // diagonal step
                    g(&mut v, &m, sigma, 0,  5, 10, 15,  8 );
                    g(&mut v, &m, sigma, 1,  6, 11, 12, 10 );
                    g(&mut v, &m, sigma, 2,  7,  8, 13, 12 );
                    g(&mut v, &m, sigma, 3,  4,  9, 14, 14 );
                }

                for (i, vx) in v.iter().enumerate() {
                    self.state.h[i % 8] ^= *vx;
                }

                for (i, hx) in self.state.h.iter_mut().enumerate() {
                    *hx ^= self.state.s[i % 4];
                }
            }
        }
    }
}

macro_rules! define_hasher {
    ($name:ident, $word:ident, $buf:expr, $Bufsz:ty, $bits:expr, $Bytes:ident,
     $serializer:path, $compressor:ident, $iv:expr) => {
        #[derive(Clone)]
        pub struct $name {
            compressor: $compressor,
            buffer: BlockBuffer<$Bufsz>,
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                f.debug_struct("Blake")
                    .field("compressor", &self.compressor)
                    .field("buffer.position()", &self.buffer.position())
                    .finish()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    compressor: $compressor {
                        state: State::<$word> {
                            h: $iv,
                            s: [0; 4],
                            t: [0; 2],
                            nullt: false,
                        }
                    },
                    buffer: BlockBuffer::default(),
                }
            }
        }

        impl digest::BlockInput for $name {
            type BlockSize = $Bytes;
        }

        impl digest::Input for $name {
            fn input<T: AsRef<[u8]>>(&mut self, data: T) {
                let compressor = &mut self.compressor;
                self.buffer.input(data.as_ref(), |block| {
                    compressor.increase_count((mem::size_of::<$word>() * 16) as $word);
                    compressor.put_block(block);
                });
            }
        }

        impl digest::FixedOutput for $name {
            type OutputSize = $Bytes;

            fn fixed_result(self) -> GenericArray<u8, $Bytes> {
                let mut compressor = self.compressor;
                let mut buffer = self.buffer;

                compressor.increase_count(buffer.position() as $word);

                let mut msglen = [0u8; $buf/8];
                $serializer(&mut msglen[..$buf/16], compressor.state.t[1]);
                $serializer(&mut msglen[$buf/16..], compressor.state.t[0]);

                let footerlen = 1 + 2 * mem::size_of::<$word>();

                // low bit indicates full-length variant
                let isfull = ($bits == 8 * mem::size_of::<[$word; 8]>()) as u8;
                // high bit indicates fit with no padding
                let exactfit = if buffer.position() + footerlen != $buf { 0x00 } else { 0x80 };
                let magic = isfull | exactfit;

                // if header won't fit in last data block, pad to the end and start a new one
                let extra_block = buffer.position() + footerlen > $buf;
                if extra_block {
                    let pad = $buf - buffer.position();
                    buffer.input(&PADDING[..pad], |block| compressor.put_block(block));
                    debug_assert_eq!(buffer.position(), 0);
                }

                // pad last block up to footer start point
                compressor.state.nullt = buffer.position() == 0;
                // skip begin-padding byte if continuing padding
                let x = extra_block as usize;
                let (start, end) = (x, x + ($buf - footerlen - buffer.position()));
                buffer.input(&PADDING[start..end], |_| unreachable!());
                buffer.input(&[magic], |_| unreachable!());
                buffer.input(&msglen, |block| compressor.put_block(block));
                debug_assert_eq!(buffer.position(), 0);

                let mut out = GenericArray::default();
                for (h, out) in compressor.state.h.iter()
                    .zip(out.chunks_mut(mem::size_of::<$word>())) {
                    $serializer(out, *h);
                }
                out
            }
        }

        impl digest::Reset for $name {
            fn reset(&mut self) {
                *self = Self::default()
            }
        }
    };
}

use block_buffer::byteorder::{ByteOrder, BE};
use consts::{
    BLAKE224_IV, BLAKE256_IV, BLAKE256_U, BLAKE384_IV, BLAKE512_IV, BLAKE512_U, PADDING, SIGMA,
};
use digest::generic_array::typenum::{U128, U28, U32, U48, U64};

#[cfg_attr(rustfmt, rustfmt_skip)]
define_compressor!(Compressor256, u32, U64, BE::read_u32, BLAKE256_U, 14, 16, 12, 8, 7);

#[cfg_attr(rustfmt, rustfmt_skip)]
define_hasher!(Blake224, u32, 64, U64, 224, U28, BE::write_u32, Compressor256, BLAKE224_IV);

#[cfg_attr(rustfmt, rustfmt_skip)]
define_hasher!(Blake256, u32, 64, U64, 256, U32, BE::write_u32, Compressor256, BLAKE256_IV);

#[cfg_attr(rustfmt, rustfmt_skip)]
define_compressor!(Compressor512, u64, U128, BE::read_u64, BLAKE512_U, 16, 32, 25, 16, 11);

#[cfg_attr(rustfmt, rustfmt_skip)]
define_hasher!(Blake384, u64, 128, U128, 384, U48, BE::write_u64, Compressor512, BLAKE384_IV);

#[cfg_attr(rustfmt, rustfmt_skip)]
define_hasher!(Blake512, u64, 128, U128, 512, U64, BE::write_u64, Compressor512, BLAKE512_IV);

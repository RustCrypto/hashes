//! An implementation of the SHA-3 cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-3 standard:
//!
//! * `SHA3-224`
//! * `SHA3-256`
//! * `SHA3-384`
//! * `SHA3-512`
//! * `SHAKE128`, an extendable output function (XOF)
//! * `SHAKE256`, an extendable output function (XOF)
//! * `Keccak224`, `Keccak256`, `Keccak384`, `Keccak512` (NIST submission
//!    without padding changes)
//!
//! # Usage
//!
//! An example of using `SHA3-256` is:
//!
//! ```rust
//! use sha3::{Digest, Sha3_256};
//!
//! // create a SHA3-256 object
//! let mut hasher = Sha3_256::default();
//!
//! // write input message
//! hasher.input(b"abc");
//!
//! // read hash digest
//! let out = hasher.result();
//!
//! println!("{:x}", out);
//! ```

#![no_std]
extern crate byte_tools;
extern crate digest;
extern crate generic_array;
extern crate digest_buffer;

pub use digest::Digest;
use digest_buffer::DigestBuffer;
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::{U28, U32, U48, U64, U72, U104, U136, U144, U168};
use core::cmp;


use byte_tools::{write_u64v_le, read_u64v_le};
#[cfg(target_endian = "little")]
use core::mem::transmute;

mod keccak;
mod consts;
#[macro_use]
mod macros;

use consts::PLEN;

#[derive(Copy, Clone)]
enum Sha3Variant {
    Keccak,
    Sha3,
    Shake,
}

/// Generic SHA-3 hasher.
#[derive(Copy, Clone)]
struct Sha3<Rate> where Rate: ArrayLength<u8>, Rate::ArrayType: Copy {
    state: [u64; PLEN],
    variant: Sha3Variant,
    buffer: DigestBuffer<Rate>,
}

type Block<BlockSize> = GenericArray<u8, BlockSize>;

fn absorb_block<R>(state: &mut [u64; PLEN], block: &Block<R>)
    where R: ArrayLength<u8>
{
    let n = R::to_usize()/8;

    let mut buf;
    let buf: &[u64] = if cfg!(target_endian = "little") {
        unsafe { transmute(block.as_slice()) }
    } else if cfg!(target_endian = "big") {
        buf = [0u64; 21];
        let buf = &mut buf[..n];
        read_u64v_le(buf, block.as_slice());
        buf
    } else { unreachable!() };

    for (d, i) in state[..n].iter_mut().zip(buf) {
        *d ^= *i;
    }

    keccak::f(state);
}

impl<Rate> Sha3<Rate>
    where Rate: ArrayLength<u8>, Rate::ArrayType: Copy
{
    fn new(variant: Sha3Variant) -> Self {
        Sha3{
            state: Default::default(), variant: variant,
            buffer: Default::default(),
        }
    }

    fn absorb(&mut self, input: &[u8]) {
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &Block<Rate>| {
            absorb_block(self_state, d);
        });
    }

    fn apply_padding(&mut self) {
        let mut buf = GenericArray::<u8, Rate>::default();
        let pos = self.buffer.position();
        let n = Rate::to_usize() - pos;
        let buf = &mut buf[..n];
        buf[0] = match self.variant {
            Sha3Variant::Keccak => 0x01,
            Sha3Variant::Sha3 => 0x06,
            Sha3Variant::Shake => 0x1f,
        };
        buf[n-1] |= 0x80;

        self.absorb(&buf);
    }

    fn readout(&self, out: &mut [u8]) {
        let mut state_copy;
        let state_ref: &[u8; PLEN*8] = if cfg!(target_endian = "little") {
            unsafe { transmute(&self.state) }
        } else if cfg!(target_endian = "big") {
            state_copy = [0u8; PLEN*8];
            write_u64v_le(&mut state_copy, &self.state);
            &state_copy
        } else { unreachable!() };

        let n = out.len();
        out.copy_from_slice(&state_ref[..n]);
    }

    fn finish(mut self, out: &mut [u8]) {
        self.apply_padding();
        assert_eq!(0, self.buffer.position());
        let mut offset = 0;

        let out_len = out.len();

        let in_len = out.len();
        let mut in_pos: usize = 0;

        // Squeeze
        while in_pos < in_len {
            let rate = Rate::to_usize();
            let off_n = offset % rate;
            let mut nread = cmp::min(rate - off_n, in_len - in_pos);
            if out_len != 0 {
                nread = cmp::min(nread, out_len - offset);
            }


            let mut state_copy;
            let state_ref: &[u8; PLEN*8] = if cfg!(target_endian = "little") {
                unsafe { transmute(&mut self.state) }
            } else if cfg!(target_endian = "big") {
                state_copy = [0u8; PLEN*8];
                write_u64v_le(&mut state_copy, &self.state);
                &state_copy
            } else { unreachable!() };


            let off = offset % Rate::to_usize();
            let part = &state_ref[off..off+nread];
            out[in_pos..in_pos+nread].copy_from_slice(part);

            in_pos += nread;

            if off_n + nread != rate {
                offset += nread;
                break;
            }

            if out_len == 0 {
                offset = 0;
            } else {
                offset += nread;
            }

            keccak::f(&mut self.state);
        }

        assert!(out_len != 0 && out_len == offset, "Not everything squeezed");
    }
}


sha3_impl!(Keccak224, U28, U144, Sha3Variant::Keccak);
sha3_impl!(Keccak256, U32, U136, Sha3Variant::Keccak);
sha3_impl!(Keccak384, U48, U104, Sha3Variant::Keccak);
sha3_impl!(Keccak512, U64, U72, Sha3Variant::Keccak);

sha3_impl!(Sha3_224, U28, U144, Sha3Variant::Sha3);
sha3_impl!(Sha3_256, U32, U136, Sha3Variant::Sha3);
sha3_impl!(Sha3_384, U48, U104, Sha3Variant::Sha3);
sha3_impl!(Sha3_512, U64, U72, Sha3Variant::Sha3);

shake_impl!(Shake128, U168, Sha3Variant::Shake);
shake_impl!(Shake256, U136, Sha3Variant::Shake);

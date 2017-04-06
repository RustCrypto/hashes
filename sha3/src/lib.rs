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
//! assert_eq!(out[..], [0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
//!                      0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
//!                      0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
//!                      0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32]);
//! ```

#![no_std]
extern crate byte_tools;
extern crate digest;
extern crate generic_array;

pub use digest::Digest;
use generic_array::GenericArray;
use generic_array::typenum::{Unsigned, U28, U32,
                             U48, U64, U72, U104, U136, U144, U168, U200};
use core::cmp;

mod keccak;
mod consts;
#[macro_use]
mod macros;

#[derive(Copy, Clone)]
enum Sha3Variant {
    Keccak,
    Sha3,
    Shake,
}

/// Generic SHA-3 hasher. 
#[derive(Copy, Clone)]
struct Sha3 {
    state: GenericArray<u8, U200>,
    // Enqueued bytes in state for absorb phase
    // Squeeze offset for squeeze phase
    offset: usize,
    rate: usize,
    variant: Sha3Variant,
}

impl Sha3 {
    fn new(rate: usize, variant: Sha3Variant) -> Self {
        Self{ state: Default::default(),
            offset: 0, rate: rate, variant: variant }
    }

    fn absorb(&mut self, data: &[u8]) {
        assert!(self.offset < self.rate);

        let in_len = data.len();
        let mut in_pos: usize = 0;

        // Absorb
        while in_pos < in_len {
            let offset = self.offset;
            let nread = cmp::min(self.rate - offset, in_len - in_pos);
            for i in 0..nread {
                self.state[offset + i] ^= data[in_pos + i];
            }
            in_pos += nread;

            if offset + nread != self.rate {
                self.offset += nread;
                break;
            }

            self.offset = 0;
            keccak::f(&mut self.state);
        }
    }

    fn finalize(&mut self) {
        let ds_len = match self.variant {
            Sha3Variant::Keccak => 0,
            Sha3Variant::Sha3 => 2,
            Sha3Variant::Shake => 4,
        };

        // All parameters are expected to be in bits.
        fn pad_len(ds_len: usize, offset: usize, rate: usize) -> usize {
            assert!(rate % 8 == 0 && offset % 8 == 0);
            let r: i64 = rate as i64;
            let m: i64 = (offset + ds_len) as i64;
            let zeros = (((-m - 2) + 2 * r) % r) as usize;
            assert!((m as usize + zeros + 2) % 8 == 0);
            (ds_len as usize + zeros + 2) / 8
        }

        fn set_pad(offset: usize, buf: &mut [u8]) {
            //assert!(buf.len() as f32 >= ((offset + 2) as f32 / 8.0).ceil());
            let s = offset / 8;
            let buflen = buf.len();
            buf[s] |= 1 << (offset % 8);
            for i in (offset % 8) + 1..8 {
                buf[s] &= !(1 << i);
            }
            for v in buf.iter_mut().skip(s + 1) {
                *v = 0;
            }
            buf[buflen - 1] |= 0x80;
        }

        let p_len = pad_len(ds_len, self.offset * 8, self.rate * 8);

        // TODO: check correctness
        const BUF_LEN: usize = 1 << 8;
        assert!(p_len < BUF_LEN);
        let mut buf = [0; BUF_LEN];
        let mut buf = &mut buf[..p_len];

        // Setting domain separator
        match self.variant {
            Sha3Variant::Keccak => (),
            Sha3Variant::Sha3 => {
                // 01...
                buf[0] &= 0xfe;
                buf[0] |= 0x2;
            },
            Sha3Variant::Shake => {
                // 1111...
                buf[0] |= 0xf;
            },
        };

        set_pad(ds_len, &mut buf);

        self.absorb(&buf);
    }

    fn finish(mut self, out: &mut [u8]) {
        self.finalize();

        let out_len = out.len();
        assert!(self.offset < out_len);
        assert!(self.offset < self.rate);

        let in_len = out.len();
        let mut in_pos: usize = 0;

        // Squeeze
        while in_pos < in_len {
            let offset = self.offset % self.rate;
            let mut nread = cmp::min(self.rate - offset, in_len - in_pos);
            if out_len != 0 {
                nread = cmp::min(nread, out_len - self.offset);
            }

            for i in 0..nread {
                out[in_pos + i] = self.state[offset + i];
            }
            in_pos += nread;

            if offset + nread != self.rate {
                self.offset += nread;
                break;
            }

            if out_len == 0 {
                self.offset = 0;
            } else {
                self.offset += nread;
            }

            keccak::f(&mut self.state);
        }

        assert!(out_len != 0 && out_len == self.offset,
            "something left to squeeze");
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

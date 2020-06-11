//! An implementation of the [Whirlpool][1] cryptographic hash algorithm.
//!
//! This is the algorithm recommended by NESSIE (New European Schemes for
//! Signatures, Integrity and Encryption; an European research project).
//!
//! The constants used by Whirlpool were changed twice (2001 and 2003) - this
//! crate only implements the most recent standard. The two older Whirlpool
//! implementations (sometimes called Whirlpool-0 (pre 2001) and Whirlpool-T
//! (pre 2003)) were not used much anyway (both have never been recommended
//! by NESSIE).
//!
//! For details see <http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html>.
//!
//! # Usage
//!
//! ```rust
//! use whirlpool::{Whirlpool, Digest};
//! use hex_literal::hex;
//!
//! // create a hasher object, to use it do not forget to import `Digest` trait
//! let mut hasher = Whirlpool::new();
//! // write input message
//! hasher.update(b"Hello Whirlpool");
//! // read hash digest (it will consume hasher)
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     8eaccdc136903c458ea0b1376be2a5fc9dc5b8ce8892a3b4f43366e2610c206c
//!     a373816495e63db0fff2ff25f75aa7162f332c9f518c3036456502a8414d300a
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Whirlpool_(hash_function)
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "asm")]
use whirlpool_asm as utils;

#[cfg(not(feature = "asm"))]
mod utils;

#[cfg(not(feature = "asm"))]
mod consts;

pub use digest::Digest;

use crate::utils::compress;

use block_buffer::{block_padding::Iso7816, BlockBuffer};
use digest::{consts::U64, generic_array::GenericArray};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

type BlockSize = U64;

/// Structure representing the state of a Whirlpool computation
#[derive(Clone)]
pub struct Whirlpool {
    bit_length: [u8; 32],
    buffer: BlockBuffer<U64>,
    #[cfg(not(feature = "asm"))]
    hash: [u64; 8],
    #[cfg(feature = "asm")]
    hash: [u8; 64],
}

impl Default for Whirlpool {
    fn default() -> Self {
        Self {
            bit_length: [0u8; 32],
            buffer: BlockBuffer::default(),
            #[cfg(not(feature = "asm"))]
            hash: [0u64; 8],
            #[cfg(feature = "asm")]
            hash: [0u8; 64],
        }
    }
}

fn convert(block: &GenericArray<u8, U64>) -> &[u8; 64] {
    #[allow(unsafe_code)]
    unsafe {
        &*(block.as_ptr() as *const [u8; 64])
    }
}

impl Whirlpool {
    #![cfg_attr(
        feature = "cargo-clippy",
        allow(clippy::identity_op, clippy::double_parens)
    )]
    fn update_len(&mut self, len: u64) {
        let len_bits = [
            (len >> (56 + 5)) as u8,
            ((len >> (48 + 5)) & 0xff) as u8,
            ((len >> (40 + 5)) & 0xff) as u8,
            ((len >> (32 + 5)) & 0xff) as u8,
            ((len >> (24 + 5)) & 0xff) as u8,
            ((len >> (16 + 5)) & 0xff) as u8,
            ((len >> (8 + 5)) & 0xff) as u8,
            ((len >> (0 + 5)) & 0xff) as u8,
            ((len << 3) & 0xff) as u8,
        ];

        let mut carry = false;
        for i in 0..32 {
            let mut x = u16::from(self.bit_length[self.bit_length.len() - i - 1]);

            if i < len_bits.len() {
                x += u16::from(len_bits[len_bits.len() - i - 1]);
            } else if !carry {
                break;
            }

            if carry {
                x += 1;
            }

            carry = x > 0xff;
            let pos = self.bit_length.len() - i - 1;
            self.bit_length[pos] = (x & 0xff) as u8;
        }
    }

    fn finalize_inner(&mut self) {
        // padding
        let hash = &mut self.hash;
        let pos = self.buffer.position();
        let buf = self
            .buffer
            .pad_with::<Iso7816>()
            .expect("we never use input_lazy");

        if pos + 1 > self.bit_length.len() {
            compress(hash, convert(buf));
            buf[..(pos + 1)].iter_mut().for_each(|b| *b = 0);
        }

        buf[32..].copy_from_slice(&self.bit_length);
        compress(hash, convert(buf));
    }
}

impl BlockInput for Whirlpool {
    type BlockSize = BlockSize;
}

impl Update for Whirlpool {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        self.update_len(input.len() as u64);
        let hash = &mut self.hash;
        self.buffer
            .input_block(input, |b| compress(hash, convert(b)));
    }
}

impl FixedOutputDirty for Whirlpool {
    type OutputSize = U64;

    #[cfg(not(feature = "asm"))]
    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, U64>) {
        self.finalize_inner();
        for (chunk, v) in out.chunks_exact_mut(8).zip(self.hash.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }

    #[cfg(feature = "asm")]
    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, U64>) {
        self.finalize_inner();
        out.copy_from_slice(&self.hash)
    }
}

impl Reset for Whirlpool {
    fn reset(&mut self) {
        self.bit_length = [0u8; 32];
        self.buffer.reset();
        for v in self.hash.iter_mut() {
            *v = 0;
        }
    }
}

opaque_debug::implement!(Whirlpool);
digest::impl_write!(Whirlpool);

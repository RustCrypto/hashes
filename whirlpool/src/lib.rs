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
//! # #[macro_use] extern crate hex_literal;
//! # extern crate whirlpool;
//! # fn main() {
//! use whirlpool::{Whirlpool, Digest};
//!
//! // create a hasher object, to use it do not forget to import `Digest` trait
//! let mut hasher = Whirlpool::new();
//! // write input message
//! hasher.input(b"Hello Whirlpool");
//! // read hash digest (it will consume hasher)
//! let result = hasher.result();
//!
//! assert_eq!(result[..], hex!("
//!     8eaccdc136903c458ea0b1376be2a5fc9dc5b8ce8892a3b4f43366e2610c206c
//!     a373816495e63db0fff2ff25f75aa7162f332c9f518c3036456502a8414d300a
//! ")[..]);
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Whirlpool_(hash_function)
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#[macro_use] extern crate opaque_debug;
#[macro_use] pub extern crate digest;
extern crate block_buffer;
extern crate byte_tools;
#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "asm")]
extern crate whirlpool_asm as utils;

#[cfg(not(feature = "asm"))]
mod utils;

use utils::compress;

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput, Reset};
#[cfg(not(feature = "asm"))]
use byte_tools::zero;
use block_buffer::BlockBuffer;
use block_buffer::block_padding::Iso7816;
use block_buffer::byteorder::{BE, ByteOrder};
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::U64;

#[cfg(not(feature = "asm"))]
mod consts;

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
    unsafe { &*(block.as_ptr() as *const [u8; 64]) }
}

impl Whirlpool {
    #![cfg_attr(feature = "cargo-clippy", allow(identity_op, double_parens))]
    fn update_len(&mut self, len: u64) {
        let len_bits = [
            ((len >> (56 + 5))       ) as u8,
            ((len >> (48 + 5)) & 0xff) as u8,
            ((len >> (40 + 5)) & 0xff) as u8,
            ((len >> (32 + 5)) & 0xff) as u8,
            ((len >> (24 + 5)) & 0xff) as u8,
            ((len >> (16 + 5)) & 0xff) as u8,
            ((len >> ( 8 + 5)) & 0xff) as u8,
            ((len >> ( 0 + 5)) & 0xff) as u8,
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
            let pos = self.bit_length.len() -i - 1;
            self.bit_length[pos] = (x & 0xff) as u8;
        }
    }

    fn finalize(&mut self) {
        // padding
        let hash = &mut self.hash;
        let pos = self.buffer.position();
        let buf = self.buffer.pad_with::<Iso7816>()
            .expect("we never use input_lazy");

        if pos + 1 > self.bit_length.len() {
            compress(hash, convert(buf));
            zero(&mut buf[..pos+1]);
        }

        buf[32..].copy_from_slice(&self.bit_length);
        compress(hash, convert(buf));
    }
}

impl BlockInput for Whirlpool {
    type BlockSize = BlockSize;
}

impl Input for Whirlpool {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        self.update_len(input.len() as u64);
        let hash = &mut self.hash;
        self.buffer.input(input, |b| compress(hash, convert(b)));
    }
}

impl FixedOutput for Whirlpool {
    type OutputSize = U64;

    #[cfg(not(feature = "asm"))]
    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        BE::write_u64_into(&self.hash[..], &mut out);
        out
    }

    #[cfg(feature = "asm")]
    fn fixed_result(&mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();
        let res = GenericArray::clone_from_slice(&self.hash);
        *self = Default::default();
        res
    }
}

impl Reset for Whirlpool {
    fn reset(&mut self) {
        self.bit_length = [0u8; 32];
        self.buffer.reset();
        for v in self.hash.iter_mut() { *v = 0; }
    }
}

impl_opaque_debug!(Whirlpool);
impl_write!(Whirlpool);

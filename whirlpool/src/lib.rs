//! An implementation of the Whirlpool cryptographic hash algorithm.
//!
//! This is the algorithm recommended by NESSIE (New European Schemes for
//! Signatures, Integrity and Encryption; an European research project).
//!
//! The constants used by Whirlpool were changed twice (2001 and 2003) - this
//! module only implements the most recent standard. The two older Whirlpool
//! implementations (sometimes called Whirlpool-0 (pre 2001) and Whirlpool-T
//! (pre 2003)) were not used much anyway (both have never been recommended
//! by NESSIE).
//!
//! For details see <http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html>.
//!
//! # Usage
//! 
//! ```rust
//! use whirlpool_asm::{Whirlpool, Digest};
//!
//! let mut hasher = Whirlpool::default();
//! hasher.input(b"Hello Whirlpool");
//! let result = hasher.result();
//! ```

#![no_std]
extern crate generic_array;
extern crate digest;
extern crate digest_buffer;

pub use digest::Digest;
use digest_buffer::DigestBuffer;
use generic_array::GenericArray;
use generic_array::typenum::U64;
use core::mem;

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;

#[link(name="whirlpool", kind="static")]
extern "C" {
    fn whirlpool_compress(state: &mut [u8; 64], block: &[u8; 64]);
}

#[inline(always)]
fn process_block(state: &mut Block, block: &Block) {
    unsafe {
        whirlpool_compress(mem::transmute(state), mem::transmute(block));
    }
}

#[derive(Copy, Clone, Default)]
pub struct Whirlpool {
    bit_length: [u8; 32],
    buffer: DigestBuffer<BlockSize>,
    hash: Block,
}

impl Whirlpool {
    fn finalize(&mut self) {
        // padding
        assert!(self.buffer.remaining() >= 1);
        let hash = &mut self.hash;
        self.buffer.input(&[0b10000000], |b| { process_block(hash, b); });

        if self.buffer.remaining() < self.bit_length.len() {
            let size = self.buffer.size();
            self.buffer.zero_until(size);
            process_block(hash, self.buffer.full_buffer());
        }

        // length
        self.buffer.zero_until(32);
        self.buffer.input(&self.bit_length, |b| { process_block(hash, b); });
        assert!(self.buffer.position() == 0);
    }
}

impl digest::Input for Whirlpool {
    type BlockSize = BlockSize;

    fn digest(&mut self, input: &[u8]) {
        // (byte length * 8) = (bit lenght) converted in a 72 bit uint
        let len = input.len() as u64;
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

        // adds the 72 bit len_bits to the 256 bit self.bit_length
        let mut carry = false;
        for i in 0..32 {
            let mut x = self.bit_length[self.bit_length.len() - i - 1] as u16;
            
            if i < len_bits.len() {
                x += len_bits[len_bits.len() - i - 1] as u16;
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

        // process the data itself
        let hash = &mut self.hash;
        self.buffer.input(input, |b| { process_block(hash, b); });
    }
}

impl digest::FixedOutput for Whirlpool {
    type OutputSize = U64;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        out.as_mut_slice().copy_from_slice(&self.hash);
        out
    }
}

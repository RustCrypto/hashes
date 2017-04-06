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
//! use whirlpool::{Whirlpool, Digest};
//!
//! let mut hasher = Whirlpool::default();
//! hasher.input(b"Hello Whirlpool");
//! let result = hasher.result();
//! ```

#![no_std]
extern crate generic_array;
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;

use core::mem::uninitialized;

pub use digest::Digest;
use byte_tools::write_u64v_be;
use digest_buffer::DigestBuffer;
use generic_array::GenericArray;
use generic_array::typenum::U64;

mod consts;
use consts::*;

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;

fn process_buffer(hash: &mut[u64; 8], buffer: &Block) {
    let mut k: [u64; 8] = unsafe { uninitialized() };
    let mut block: [u64; 8] = unsafe { uninitialized() };
    let mut state: [u64; 8] = unsafe { uninitialized() };
    let mut l: [u64; 8] = unsafe { uninitialized() };

    for i in 0..8 {
        block[i] =
            ((buffer[i * 8 + 0] as u64) << 56) ^
            ((buffer[i * 8 + 1] as u64) << 48) ^
            ((buffer[i * 8 + 2] as u64) << 40) ^
            ((buffer[i * 8 + 3] as u64) << 32) ^
            ((buffer[i * 8 + 4] as u64) << 24) ^
            ((buffer[i * 8 + 5] as u64) << 16) ^
            ((buffer[i * 8 + 6] as u64) <<  8) ^
            ((buffer[i * 8 + 7] as u64)      );
        k[i] = hash[i];
        state[i] = block[i] ^ k[i];
    }

    for r in 1..(R + 1) /* [1, R] */ {
        for i in 0..8 {
            l[i] =
                C0[((k[(0 + i) % 8] >> 56)       ) as usize] ^
                C1[((k[(7 + i) % 8] >> 48) & 0xff) as usize] ^
                C2[((k[(6 + i) % 8] >> 40) & 0xff) as usize] ^
                C3[((k[(5 + i) % 8] >> 32) & 0xff) as usize] ^
                C4[((k[(4 + i) % 8] >> 24) & 0xff) as usize] ^
                C5[((k[(3 + i) % 8] >> 16) & 0xff) as usize] ^
                C6[((k[(2 + i) % 8] >>  8) & 0xff) as usize] ^
                C7[((k[(1 + i) % 8]      ) & 0xff) as usize] ^
                if i == 0 { RC[r] } else { 0 };
        }
        k = l;
        for i in 0..8 {
            l[i] =
                C0[((state[(0 + i) % 8] >> 56)       ) as usize] ^
                C1[((state[(7 + i) % 8] >> 48) & 0xff) as usize] ^
                C2[((state[(6 + i) % 8] >> 40) & 0xff) as usize] ^
                C3[((state[(5 + i) % 8] >> 32) & 0xff) as usize] ^
                C4[((state[(4 + i) % 8] >> 24) & 0xff) as usize] ^
                C5[((state[(3 + i) % 8] >> 16) & 0xff) as usize] ^
                C6[((state[(2 + i) % 8] >>  8) & 0xff) as usize] ^
                C7[((state[(1 + i) % 8]      ) & 0xff) as usize] ^
                k[i];
        }
        state = l;
    }

    for i in 0..8 {
        hash[i] ^= state[i] ^ block[i];
    }
}

#[derive(Copy, Clone, Default)]
pub struct Whirlpool {
    bit_length: [u8; 32],
    buffer: DigestBuffer<BlockSize>,
    hash: [u64; 8],
}

impl Whirlpool {
    fn finalize(&mut self) {
        // padding
        assert!(self.buffer.remaining() >= 1);
        let hash = &mut self.hash;
        self.buffer.input(&[0b10000000], |b| { process_buffer(hash, b); });

        if self.buffer.remaining() < self.bit_length.len() {
            let size = self.buffer.size();
            self.buffer.zero_until(size);
            process_buffer(hash, self.buffer.full_buffer());
        }

        // length
        self.buffer.zero_until(32);
        self.buffer.input(&self.bit_length, |b| { process_buffer(hash, b); });
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
        self.buffer.input(input, |b| { process_buffer(hash, b); });
    }
}

impl digest::FixedOutput for Whirlpool {
    type OutputSize = U64;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        write_u64v_be(&mut out, &self.hash[..]);
        out
    }
}

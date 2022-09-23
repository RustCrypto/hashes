//! Pure Rust implementation of the [BelT] hash function specified in
//! [STB 34.101.31-2020].
//!
//! # Usage
//!
//! ```rust
//! use belt_hash::{BeltHash, Digest};
//! use hex_literal::hex;
//!
//! // create a BelT hasher instance
//! let mut hasher = BeltHash::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let result = hasher.finalize();
//! let expected = hex!(
//!     "afb175816416fbadad4629ecbd78e1887789881f2d2e5b80c22a746b7ac7ba88"
//! );
//! assert_eq!(result[..], expected[..]);
//! ```
//!
//! Also see [examples] in the RustCrypto/hashes readme.
//!
//! [BelT]: https://ru.wikipedia.org/wiki/BelT
//! [STB 34.101.31-2020]: http://apmi.bsu.by/assets/files/std/belt-spec371.pdf
//! [examples]: https://github.com/RustCrypto/hashes#usage
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

pub use digest::{self, Digest};

use belt_block::belt_block_raw;
use core::fmt;
#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U32},
    HashMarker, Output,
};

const U32_MASK: u128 = (1 << 32) - 1;

/// Core BelT hasher state.
#[derive(Clone)]
pub struct BeltHashCore {
    r: u128,
    s: [u32; 4],
    h: [u32; 8],
}

impl BeltHashCore {
    fn compress_block(&mut self, block: &Block<Self>) {
        let x1 = [
            get_u32(block, 0),
            get_u32(block, 1),
            get_u32(block, 2),
            get_u32(block, 3),
        ];
        let x2 = [
            get_u32(block, 4),
            get_u32(block, 5),
            get_u32(block, 6),
            get_u32(block, 7),
        ];
        let (t, h) = belt_compress(x1, x2, self.h);
        self.h = h;
        self.s.iter_mut().zip(t).for_each(|(s, t)| *s ^= t);
    }
}

impl HashMarker for BeltHashCore {}

impl BlockSizeUser for BeltHashCore {
    type BlockSize = U32;
}

impl BufferKindUser for BeltHashCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for BeltHashCore {
    type OutputSize = U32;
}

impl UpdateCore for BeltHashCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.r = self.r.wrapping_add(blocks.len() as u128);
        for block in blocks {
            self.compress_block(block);
        }
    }
}

impl FixedOutputCore for BeltHashCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        if pos != 0 {
            let block = buffer.pad_with_zeros();
            self.compress_block(block);
        }
        let bs = Self::BlockSize::USIZE as u128;
        let r = encode_r(8 * ((bs * self.r) + pos as u128));
        let (_, y) = belt_compress(r, self.s, self.h);
        for (chunk, val) in out.chunks_exact_mut(4).zip(y) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
    }
}

impl Default for BeltHashCore {
    #[inline]
    fn default() -> Self {
        Self {
            r: 0,
            s: [0; 4],
            #[rustfmt::skip]
            h: [
                0xC8BA94B1, 0x3BF5080A, 0x8E006D36, 0xE45D4A58,
                0x9DFA0485, 0xACC7B61B, 0xC2722E25, 0x0DCEFD02,
            ],
        }
    }
}

impl Reset for BeltHashCore {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for BeltHashCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltHash")
    }
}

impl fmt::Debug for BeltHashCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltHashCore { ... }")
    }
}

#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
impl AssociatedOid for BeltHashCore {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.31.81");
}

/// BelT hasher state.
pub type BeltHash = CoreWrapper<BeltHashCore>;

/// Compression function described in the section 6.3.2
#[inline(always)]
fn belt_compress(x1: [u32; 4], x2: [u32; 4], x34: [u32; 8]) -> ([u32; 4], [u32; 8]) {
    let x3 = [x34[0], x34[1], x34[2], x34[3]];
    let x4 = [x34[4], x34[5], x34[6], x34[7]];

    // Step 2
    let t1 = belt_block_raw(xor(x3, x4), &concat(x1, x2));
    let s = xor(xor(t1, x3), x4);
    // Step 3
    let t2 = belt_block_raw(x1, &concat(s, x4));
    let y1 = xor(t2, x1);
    // Step 4
    let t3 = belt_block_raw(x2, &concat(s.map(|v| !v), x3));
    let y2 = xor(t3, x2);
    // Step 5
    (s, concat(y1, y2))
}

#[inline(always)]
fn xor(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    // TODO: use array zip on stabilization and MSRV bump
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

#[inline(always)]
fn concat(a: [u32; 4], b: [u32; 4]) -> [u32; 8] {
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

#[inline(always)]
fn get_u32(block: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(block[4 * i..][..4].try_into().unwrap())
}

#[inline(always)]
fn encode_r(r: u128) -> [u32; 4] {
    [
        (r & U32_MASK) as u32,
        ((r >> 32) & U32_MASK) as u32,
        ((r >> 64) & U32_MASK) as u32,
        ((r >> 96) & U32_MASK) as u32,
    ]
}

#[cfg(test)]
mod tests {
    use super::{belt_compress, get_u32};
    use hex_literal::hex;

    const ENUM4: [usize; 4] = [0, 1, 2, 3];
    const ENUM8: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    /// Test vectors for the `belt-compress` functions from the
    /// specification (Table A.8).
    #[test]
    fn compress() {
        let x = &hex!(
            "B194BAC8 0A08F53B 366D008E 584A5DE4"
            "8504FA9D 1BB6C7AC 252E72C2 02FDCE0D"
            "5BE3D612 17B96181 FE6786AD 716B890B"
            "5CB0C0FF 33C356B8 35C405AE D8E07F99"
        );
        let expected_s = &hex!("46FE7425 C9B181EB 41DFEE3E 72163D5A");
        let expected_y = &hex!(
            "ED2F5481 D593F40D 87FCE37D 6BC1A2E1"
            "B7D1A2CC 975C82D3 C0497488 C90D99D8"
        );
        let x1 = ENUM4.map(|i| get_u32(x, i));
        let x2 = ENUM4.map(|i| get_u32(x, 4 + i));
        let x34 = ENUM8.map(|i| get_u32(x, 8 + i));

        let (s, y) = belt_compress(x1, x2, x34);

        assert_eq!(s, ENUM4.map(|i| get_u32(expected_s, i)));
        assert_eq!(y, ENUM8.map(|i| get_u32(expected_y, i)));
    }
}

//! An implementation of the [MD4][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! use md4::{Md4, Digest};
//! use hex_literal::hex;
//!
//! // create a Md4 hasher instance
//! let mut hasher = Md4::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("aa010fbc1d14c795d86ef98c95479d17"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/MD4
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub use digest::{self, Digest};

use core::{convert::TryInto, fmt, num::Wrapping as W};
#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U16, U64},
    HashMarker, Output,
};

type Wu32 = W<u32>;
const S0: [Wu32; 4] = [
    W(0x6745_2301),
    W(0xEFCD_AB89),
    W(0x98BA_DCFE),
    W(0x1032_5476),
];
const K1: Wu32 = W(0x5A82_7999);
const K2: Wu32 = W(0x6ED9_EBA1);

#[derive(Clone)]
pub struct Md4Core {
    block_len: W<u64>,
    state: [Wu32; 4],
}

impl HashMarker for Md4Core {}

impl BlockSizeUser for Md4Core {
    type BlockSize = U64;
}

impl BufferKindUser for Md4Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Md4Core {
    type OutputSize = U16;
}

impl UpdateCore for Md4Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += W(blocks.len() as u64);
        for block in blocks {
            compress(&mut self.state, block);
        }
    }
}

impl FixedOutputCore for Md4Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let tail_len = W(buffer.get_pos() as u64);
        let bytes_len = W(Self::BlockSize::U64) * self.block_len + tail_len;
        let bits_len = W(8) * bytes_len;

        let mut state = self.state;
        buffer.len64_padding_le(bits_len.0, |block| compress(&mut state, block));

        for (chunk, v) in out.chunks_exact_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&v.0.to_le_bytes());
        }
    }
}

impl Default for Md4Core {
    #[inline]
    fn default() -> Self {
        Self {
            state: S0,
            block_len: W(0),
        }
    }
}

impl Reset for Md4Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Md4Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md4")
    }
}

impl fmt::Debug for Md4Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md4Core { ... }")
    }
}

#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
impl AssociatedOid for Md4Core {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.4");
}

/// MD4 hasher state.
pub type Md4 = CoreWrapper<Md4Core>;

fn compress(state: &mut [Wu32; 4], input: &Block<Md4Core>) {
    fn f(x: Wu32, y: Wu32, z: Wu32) -> Wu32 {
        z ^ (x & (y ^ z))
    }

    fn g(x: Wu32, y: Wu32, z: Wu32) -> Wu32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: Wu32, y: Wu32, z: Wu32) -> Wu32 {
        x ^ y ^ z
    }

    fn op<F>(f: F, a: Wu32, b: Wu32, c: Wu32, d: Wu32, k: Wu32, s: u32) -> Wu32
    where
        F: Fn(Wu32, Wu32, Wu32) -> Wu32,
    {
        let t = a + f(b, c, d) + k;
        W(t.0.rotate_left(s))
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    // load block to data
    let mut data = [W(0u32); 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = W(u32::from_le_bytes(chunk.try_into().unwrap()));
    }

    // round 1
    for &i in &[0, 4, 8, 12] {
        a = op(f, a, b, c, d, data[i], 3);
        d = op(f, d, a, b, c, data[i + 1], 7);
        c = op(f, c, d, a, b, data[i + 2], 11);
        b = op(f, b, c, d, a, data[i + 3], 19);
    }

    // round 2
    for &i in &[0, 1, 2, 3] {
        a = op(g, a, b, c, d, data[i] + K1, 3);
        d = op(g, d, a, b, c, data[i + 4] + K1, 5);
        c = op(g, c, d, a, b, data[i + 8] + K1, 9);
        b = op(g, b, c, d, a, data[i + 12] + K1, 13);
    }

    // round 3
    for &i in &[0, 2, 1, 3] {
        a = op(h, a, b, c, d, data[i] + K2, 3);
        d = op(h, d, a, b, c, data[i + 8] + K2, 9);
        c = op(h, c, d, a, b, data[i + 4] + K2, 11);
        b = op(h, b, c, d, a, data[i + 12] + K2, 15);
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]
#![warn(unreachable_pub)]

pub use digest;

use core::fmt;
use digest::{
    CollisionResistance, CustomizedInit, ExtendableOutput, HashMarker, Update, XofReader,
    array::Array,
    block_api::{AlgorithmName, BlockSizeUser},
    block_buffer::{BlockSizes, EagerBuffer, LazyBuffer, ReadBuffer},
    consts::{U16, U32, U136, U168},
};
use keccak::{Keccak, State1600};

const SHAKE_PAD: u8 = 0x1F;
const CSHAKE_PAD: u8 = 0x04;

/// cSHAKE128 hasher.
pub type CShake128 = CShake<U168>;
/// cSHAKE256 hasher.
pub type CShake256 = CShake<U136>;

/// cSHAKE hasher generic over rate.
///
/// Rate MUST be either [`U168`] or [`U136`] for cSHAKE128 and cSHAKE256 respectively.
#[derive(Clone)]
pub struct CShake<Rate: BlockSizes> {
    state: State1600,
    buffer: EagerBuffer<Rate>,
    pad: u8,
    keccak: Keccak,
}

impl<Rate: BlockSizes> Default for CShake<Rate> {
    #[inline]
    fn default() -> Self {
        Self::new_with_function_name(b"", b"")
    }
}

impl<Rate: BlockSizes> CShake<Rate> {
    /// Creates a new cSHAKE instance with the given function name and customization.
    ///
    /// Note that the function name is intended for use by NIST and should only be set to
    /// values defined by NIST. You probably don't need to use this function.
    pub fn new_with_function_name(function_name: &[u8], customization: &[u8]) -> Self {
        const {
            assert!(Rate::USIZE == 168 || Rate::USIZE == 136, "unsupported rate");
        }

        let buffer = Default::default();
        let keccak = Keccak::new();
        let mut state = State1600::default();

        if function_name.is_empty() && customization.is_empty() {
            return Self {
                state,
                buffer,
                keccak,
                pad: SHAKE_PAD,
            };
        }

        #[inline(always)]
        fn left_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
            b[1..].copy_from_slice(&val.to_be_bytes());
            let i = b[1..8].iter().take_while(|&&a| a == 0).count();
            b[i] = (8 - i) as u8;
            &b[i..]
        }

        keccak.with_f1600(|f1600| {
            let mut buffer: LazyBuffer<Rate> = Default::default();
            let state = &mut state;
            let mut b = [0u8; 9];

            buffer.digest_blocks(left_encode(Rate::U64, &mut b), |blocks| {
                update_blocks(f1600, state, blocks)
            });

            let mut encode_str = |str: &[u8]| {
                let str_bits_len = 8 * u64::try_from(str.len())
                    .expect("in practice strings can not be longer than u64::MAX");
                let encoded_len = left_encode(str_bits_len, &mut b);
                buffer.digest_blocks(encoded_len, |blocks| update_blocks(f1600, state, blocks));
                buffer.digest_blocks(str, |blocks| update_blocks(f1600, state, blocks));
            };

            encode_str(function_name);
            encode_str(customization);

            update_blocks(f1600, state, &[buffer.pad_with_zeros()])
        });

        Self {
            state,
            buffer,
            keccak,
            pad: CSHAKE_PAD,
        }
    }
}

impl<Rate: BlockSizes> CustomizedInit for CShake<Rate> {
    #[inline]
    fn new_customized(customization: &[u8]) -> Self {
        Self::new_with_function_name(&[], customization)
    }
}

impl<Rate: BlockSizes> HashMarker for CShake<Rate> {}

impl<Rate: BlockSizes> BlockSizeUser for CShake<Rate> {
    type BlockSize = Rate;
}

impl<Rate: BlockSizes> Update for CShake<Rate> {
    fn update(&mut self, data: &[u8]) {
        let Self {
            state,
            buffer,
            keccak,
            ..
        } = self;

        keccak.with_f1600(|f1600| {
            buffer.digest_blocks(data, |blocks| update_blocks(f1600, state, blocks));
        });
    }
}

impl<Rate: BlockSizes> CShake<Rate> {
    fn finalize_dirty(&mut self) {
        let Self {
            state,
            buffer,
            pad,
            keccak,
        } = self;

        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = *pad;
        let n = block.len();
        block[n - 1] |= 0x80;

        keccak.with_f1600(|f1600| {
            xor_block(state, &block);
            f1600(state);
        });
    }
}

impl<Rate: BlockSizes> ExtendableOutput for CShake<Rate> {
    type Reader = CShakeReader<Rate>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.finalize_dirty();
        Self::Reader {
            state: self.state,
            keccak: self.keccak,
            buffer: Default::default(),
        }
    }
}

impl<Rate: BlockSizes> AlgorithmName for CShake<Rate> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg_name = match Rate::USIZE {
            168 => "cSHAKE128",
            136 => "cSHAKE256",
            _ => unreachable!(),
        };
        f.write_str(alg_name)
    }
}

impl<Rate: BlockSizes> fmt::Debug for CShake<Rate> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match Rate::USIZE {
            168 => "CShake128 { ... }",
            136 => "CShake256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<Rate: BlockSizes> Drop for CShake<Rate> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.pad.zeroize();
            // self.buffer is zeroized by its `Drop`
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate: BlockSizes> digest::zeroize::ZeroizeOnDrop for CShake<Rate> {}

/// Generic cSHAKE XOF reader
#[derive(Clone)]
pub struct CShakeReader<Rate: BlockSizes> {
    state: State1600,
    keccak: Keccak,
    buffer: ReadBuffer<Rate>,
}

impl<Rate: BlockSizes> XofReader for CShakeReader<Rate> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        let Self {
            state,
            keccak,
            buffer,
        } = self;

        buffer.read(buf, |block| {
            let mut chunks = block.chunks_exact_mut(8);
            for (src, dst) in state.iter().zip(&mut chunks) {
                dst.copy_from_slice(&src.to_le_bytes());
            }
            assert!(
                chunks.into_remainder().is_empty(),
                "rate is either 136 or 168",
            );
            keccak.with_f1600(|f1600| f1600(state));
        });
    }
}

impl<Rate: BlockSizes> fmt::Debug for CShakeReader<Rate> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match Rate::USIZE {
            168 => "TurboShakeReader128 { ... }",
            136 => "TurboShakeReader256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<Rate: BlockSizes> Drop for CShakeReader<Rate> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            // self.buffer is zeroized by its `Drop`
        }
    }
}

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf#[{"num":68,"gen":0},{"name":"XYZ"},108,440,null]
impl CollisionResistance for CShake128 {
    type CollisionResistance = U16;
}
impl CollisionResistance for CShake256 {
    type CollisionResistance = U32;
}

fn xor_block(state: &mut State1600, block: &[u8]) {
    assert!(size_of_val(block) < size_of_val(state));

    let mut chunks = block.chunks_exact(8);
    for (s, chunk) in state.iter_mut().zip(&mut chunks) {
        *s ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }

    let rem = chunks.remainder();
    assert!(rem.is_empty(), "block size is equal to 136 or 168");
}

fn update_blocks<N: BlockSizes>(
    f1600: keccak::Fn1600,
    state: &mut State1600,
    blocks: &[Array<u8, N>],
) {
    for block in blocks {
        xor_block(state, block);
        f1600(state);
    }
}

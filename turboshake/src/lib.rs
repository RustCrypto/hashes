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
use keccak::{Keccak, State1600};

use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, Update, XofReader,
    block_api::{AlgorithmName, BlockSizeUser, Reset},
    block_buffer::{BlockSizes, EagerBuffer, ReadBuffer},
    consts::{U16, U32, U136, U168},
};

/// Number of Keccak rounds used by TurboSHAKE.
const ROUNDS: usize = 12;

/// Default domain separator value.
pub const DEFAULT_DS: u8 = 0x1F;

/// TurboSHAKE hasher generic over rate and domain separator.
///
/// Domain separator `DS` MUST be in the range `0x01..=0x7f`.
/// Use [`DEFAULT_DS`] if you want the default value.
///
/// Rate MUST be either [`U168`] or [`U136`] for TurboSHAKE128 and TurboSHAKE256 respectively.
#[derive(Clone)]
pub struct TurboShake<Rate: BlockSizes, const DS: u8> {
    state: State1600,
    keccak: Keccak,
    buffer: EagerBuffer<Rate>,
}

impl<Rate: BlockSizes, const DS: u8> Default for TurboShake<Rate, DS> {
    #[inline]
    fn default() -> Self {
        const {
            assert!(DS >= 0x01 && DS <= 0x7F, "invalid domain separator");
            assert!(Rate::USIZE == 168 || Rate::USIZE == 136, "unsupported rate");
        }
        Self {
            state: Default::default(),
            keccak: Keccak::new(),
            buffer: Default::default(),
        }
    }
}

impl<Rate: BlockSizes, const DS: u8> HashMarker for TurboShake<Rate, DS> {}

impl<Rate: BlockSizes, const DS: u8> BlockSizeUser for TurboShake<Rate, DS> {
    type BlockSize = Rate;
}

impl<Rate: BlockSizes, const DS: u8> Update for TurboShake<Rate, DS> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        let Self {
            state,
            keccak,
            buffer,
        } = self;

        keccak.with_p1600::<ROUNDS>(|p1600| {
            buffer.digest_blocks(data, |blocks| {
                for block in blocks {
                    xor_block(state, block);
                    p1600(state);
                }
            });
        });
    }
}

impl<Rate: BlockSizes, const DS: u8> TurboShake<Rate, DS> {
    fn finalize_dirty(&mut self) {
        let Self {
            state,
            keccak,
            buffer,
        } = self;

        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = DS;
        let n = block.len();
        block[n - 1] |= 0x80;

        keccak.with_p1600::<ROUNDS>(|p1600| {
            xor_block(state, &block);
            p1600(state);
        });
    }
}

impl<Rate: BlockSizes, const DS: u8> ExtendableOutput for TurboShake<Rate, DS> {
    type Reader = TurboShakeReader<Rate>;

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

impl<Rate: BlockSizes, const DS: u8> ExtendableOutputReset for TurboShake<Rate, DS> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.finalize_dirty();
        let reader = Self::Reader {
            state: self.state,
            keccak: self.keccak,
            buffer: Default::default(),
        };
        self.reset();
        reader
    }
}

impl<Rate: BlockSizes, const DS: u8> Reset for TurboShake<Rate, DS> {
    #[inline]
    fn reset(&mut self) {
        self.state = Default::default();
        self.buffer.reset();
    }
}

impl<Rate: BlockSizes, const DS: u8> AlgorithmName for TurboShake<Rate, DS> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg_name = match Rate::USIZE {
            168 => "TurboSHAKE128",
            136 => "TurboSHAKE256",
            _ => unreachable!(),
        };
        f.write_str(alg_name)
    }
}

impl<Rate: BlockSizes, const DS: u8> fmt::Debug for TurboShake<Rate, DS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match Rate::USIZE {
            168 => "TurboShake128 { ... }",
            136 => "TurboShake256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<Rate: BlockSizes, const DS: u8> Drop for TurboShake<Rate, DS> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            // self.buffer is zeroized by its `Drop`
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate: BlockSizes, const DS: u8> digest::zeroize::ZeroizeOnDrop for TurboShake<Rate, DS> {}

/// Generic TurboSHAKE XOF reader
#[derive(Clone)]
pub struct TurboShakeReader<Rate: BlockSizes> {
    state: State1600,
    keccak: Keccak,
    buffer: ReadBuffer<Rate>,
}

impl<Rate: BlockSizes> XofReader for TurboShakeReader<Rate> {
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
            keccak.with_p1600::<ROUNDS>(|p1600| p1600(state));
        });
    }
}

impl<Rate: BlockSizes> fmt::Debug for TurboShakeReader<Rate> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match Rate::USIZE {
            168 => "TurboShakeReader128 { ... }",
            136 => "TurboShakeReader256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<Rate: BlockSizes> Drop for TurboShakeReader<Rate> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            // self.buffer is zeroized by its `Drop`
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate: BlockSizes> digest::zeroize::ZeroizeOnDrop for TurboShakeReader<Rate> {}

/// TurboSHAKE128 hasher with domain separator.
pub type TurboShake128<const DS: u8 = DEFAULT_DS> = TurboShake<U168, DS>;
/// TurboSHAKE256 hasher with domain separator.
pub type TurboShake256<const DS: u8 = DEFAULT_DS> = TurboShake<U136, DS>;

/// TurboSHAKE128 XOF reader.
pub type TurboShake128Reader = TurboShakeReader<U168>;
/// TurboSHAKE256 XOF reader.
pub type TurboShake256Reader = TurboShakeReader<U136>;

impl<const DS: u8> CollisionResistance for TurboShake128<DS> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-7
    type CollisionResistance = U16;
}

impl<const DS: u8> CollisionResistance for TurboShake256<DS> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-8
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

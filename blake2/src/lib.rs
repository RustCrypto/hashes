#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(unexpected_cfgs)] // `simd` feature is broken
#![warn(missing_docs, unreachable_pub)]
#![cfg_attr(feature = "simd", feature(platform_intrinsics, repr_simd))]
#![cfg_attr(feature = "simd", allow(incomplete_features))]

pub use digest::{self, Digest};

use core::{fmt, marker::PhantomData};
use digest::{
    CustomizedInit, FixedOutput, HashMarker, InvalidOutputSize, MacMarker, Output, Update,
    array::{Array, ArraySize},
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser, TruncSide,
        UpdateCore, VariableOutputCore, VariableOutputCoreCustomized,
    },
    block_buffer::{Lazy, LazyBuffer},
    consts::{U16, U32, U64, U128},
    crypto_common::{InvalidLength, Key, KeyInit, KeySizeUser},
    typenum::{IsLessOrEqual, True, Unsigned},
};
#[cfg(feature = "reset")]
use digest::{FixedOutputReset, Reset};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

mod as_bytes;
mod blake2x;
mod consts;

mod simd;

#[macro_use]
mod macros;

use as_bytes::AsBytes;
pub use blake2x::Blake2XbReader;
use consts::{BLAKE2B_IV, BLAKE2S_IV};
use simd::{Vector4, u32x4, u64x4};

blake2_impl!(
    Blake2bVarCore,
    "Blake2b",
    u64,
    u64x4,
    U64,
    U128,
    32,
    24,
    16,
    63,
    BLAKE2B_IV,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
);

digest::buffer_ct_variable!(
    /// BLAKE2b generic over output size.
    pub struct Blake2b<OutSize>(Blake2bVarCore);
    exclude: SerializableState;
    max_size: U64;
);

// TODO: impl in the macro
impl<OutSize> CustomizedInit for Blake2b<OutSize>
where
    OutSize: ArraySize + IsLessOrEqual<U64, Output = True>,
{
    fn new_customized(customization: &[u8]) -> Self {
        Self {
            core: CustomizedInit::new_customized(customization),
            buffer: Default::default(),
        }
    }
}

/// BLAKE2b-128 hasher state.
pub type Blake2b128 = Blake2b<U16>;
/// BLAKE2b-256 hasher state.
pub type Blake2b256 = Blake2b<U32>;
/// BLAKE2b-512 hasher state.
pub type Blake2b512 = Blake2b<U64>;

blake2_mac_impl!(Blake2bMac, Blake2bVarCore, U64, "Blake2b MAC function");

/// Create a blake2xb generator with maximum output
pub fn blake2xb(seed: &[u8]) -> Blake2XbReader {
    use digest::ExtendableOutput;
    blake2x::Blake2Xb::new(Some(seed), None)
        .unwrap()
        .finalize_xof()
}

/// BLAKE2b-512 MAC state.
pub type Blake2bMac512 = Blake2bMac<U64>;

blake2_impl!(
    Blake2sVarCore,
    "Blake2s",
    u32,
    u32x4,
    U32,
    U64,
    16,
    12,
    8,
    7,
    BLAKE2S_IV,
    "Blake2s instance with a variable output.",
    "Blake2s instance with a fixed output.",
);

digest::buffer_ct_variable!(
    /// BLAKE2s generic over output size.
    pub struct Blake2s<OutSize>(Blake2sVarCore);
    exclude: SerializableState;
    max_size: U32;
);

// TODO: impl in the macro
impl<OutSize> CustomizedInit for Blake2s<OutSize>
where
    OutSize: ArraySize + IsLessOrEqual<U32, Output = True>,
{
    fn new_customized(customization: &[u8]) -> Self {
        Self {
            core: CustomizedInit::new_customized(customization),
            buffer: Default::default(),
        }
    }
}

/// BLAKE2s-128 hasher state.
pub type Blake2s128 = Blake2s<U16>;
/// BLAKE2s-256 hasher state.
pub type Blake2s256 = Blake2s<U32>;

blake2_mac_impl!(Blake2sMac, Blake2sVarCore, U32, "Blake2s MAC function");

/// BLAKE2s-256 MAC state.
pub type Blake2sMac256 = Blake2sMac<U32>;

#[derive(Clone, Copy, Default)]
struct Blake2Parameters<'a> {
    digest_length: u8,
    key_size: u8,
    fanout: u8,
    depth: u8,
    leaf_length: u32,
    node_offset: u64,
    xof_digest_length: Option<u32>,
    node_depth: u8,
    inner_length: u8,
    salt: &'a [u8],
    persona: &'a [u8],
}

macro_rules! pair_from_bytes {
    ($word:ident, $data:expr, $dword_len:literal) => {
        if $data.len() < $dword_len {
            let mut padded_data = [0; $dword_len];
            for i in 0..$data.len() {
                padded_data[i] = $data[i];
            }
            (
                $word::from_le_bytes(padded_data[0..$dword_len / 2].try_into().unwrap()),
                $word::from_le_bytes(
                    padded_data[$dword_len / 2..padded_data.len()]
                        .try_into()
                        .unwrap(),
                ),
            )
        } else {
            (
                $word::from_le_bytes($data[0..$data.len() / 2].try_into().unwrap()),
                $word::from_le_bytes($data[$data.len() / 2..$data.len()].try_into().unwrap()),
            )
        }
    };
}

// Private helper trait
trait ToParamBlock<W> {
    fn to_param_block(self) -> [W; 8];
}

impl ToParamBlock<u64> for Blake2Parameters<'_> {
    fn to_param_block(self) -> [u64; 8] {
        assert!(self.key_size <= 64);
        assert!(self.digest_length <= 64);

        // The number of bytes needed to express two words.
        let length = 16;
        assert!(self.salt.len() <= length);
        assert!(self.persona.len() <= length);

        // Build a parameter block
        let mut p = [0; 8];
        p[0] = (self.digest_length as u64)
            ^ ((self.key_size as u64) << 8)
            ^ ((self.fanout as u64) << 16)
            ^ ((self.depth as u64) << 24)
            ^ ((self.leaf_length as u64) << 32);

        p[1] = match self.xof_digest_length {
            None => self.node_offset,
            Some(xof_len) => {
                assert!(self.node_offset <= u32::MAX as u64);
                self.node_offset ^ ((xof_len as u64) << 32)
            }
        };
        p[2] = (self.node_depth as u64) ^ ((self.inner_length as u64) << 8);

        // salt is two words long
        (p[4], p[5]) = pair_from_bytes!(u64, self.salt, 16);
        // persona is also two words long
        (p[6], p[7]) = pair_from_bytes!(u64, self.persona, 16);

        p
    }
}

impl ToParamBlock<u32> for Blake2Parameters<'_> {
    fn to_param_block(self) -> [u32; 8] {
        assert!(self.key_size <= 32);
        assert!(self.digest_length <= 32);

        // The number of bytes needed to express two words.
        let length = 8;
        assert!(self.salt.len() <= length);
        assert!(self.persona.len() <= length);

        // Build a parameter block
        let mut p = [0; 8];
        p[0] = (self.digest_length as u32)
            ^ ((self.key_size as u32) << 8)
            ^ ((self.fanout as u32) << 16)
            ^ ((self.depth as u32) << 24);
        p[1] = self.leaf_length.to_le();

        (p[2], p[3]) = match self.xof_digest_length {
            None => {
                assert!(self.node_offset < 1 << 48);
                pair_from_bytes!(u32, self.node_offset.to_le_bytes(), 8)
            }
            Some(xof_len) => {
                assert!(self.node_offset <= u32::MAX as u64);
                ((self.node_offset as u32).to_le(), xof_len.to_le())
            }
        };
        p[3] ^= ((self.node_depth as u32) << 16) ^ ((self.inner_length as u32) << 24);

        // salt is two words long
        (p[4], p[5]) = pair_from_bytes!(u32, self.salt, 8);
        // persona is also two words long
        (p[6], p[7]) = pair_from_bytes!(u32, self.persona, 8);

        p
    }
}

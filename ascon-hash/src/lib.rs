// Copyright 2022-2023 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs)]

//! ## Usage (Hashing)
//!
//! ```
//! use ascon_hash::{AsconHash, Digest}; // Or `AsconAHash`
//!
//! let mut hasher = AsconHash::new();
//! hasher.update(b"some bytes");
//! let digest = hasher.finalize();
//! assert_eq!(&digest[..], b"\xb7\x42\xca\x75\xe5\x70\x38\x75\x70\x59\xcc\xcc\x68\x74\x71\x4f\x9d\xbd\x7f\xc5\x92\x4a\x7d\xf4\xe3\x16\x59\x4f\xd1\x42\x6c\xa8");
//! ```
//!
//! ## Usage (XOF)
//!
//! ```
//! use ascon_hash::{AsconXof, ExtendableOutput, Update, XofReader};
//!
//! let mut xof = AsconXof::default();
//! xof.update(b"some bytes");
//! let mut reader = xof.finalize_xof();
//! let mut dst = [0u8; 5];
//! reader.read(&mut dst);
//! assert_eq!(&dst, b"\xc2\x19\x72\xfd\xe9");
//! ```

use core::marker::PhantomData;

use ascon::{pad, State};
pub use digest::{self, Digest, ExtendableOutput, Reset, Update, XofReader};
use digest::{
    block_buffer::Eager,
    consts::{U32, U8},
    core_api::{
        AlgorithmName, Block, Buffer, BufferKindUser, CoreWrapper, ExtendableOutputCore,
        FixedOutputCore, UpdateCore, XofReaderCore, XofReaderCoreWrapper,
    },
    crypto_common::BlockSizeUser,
    HashMarker, Output, OutputSizeUser,
};

/// Parameters for Ascon hash instances.
trait HashParameters {
    /// Number of rounds for the permutation.
    const ROUNDS: usize;
    /// Part of the IV.
    const IV0: u64;
    /// Part of the IV.
    const IV1: u64;
    /// Part of the IV.
    const IV2: u64;
    /// Part of the IV.
    const IV3: u64;
    /// Part of the IV.
    const IV4: u64;
}

/// Parameters for AsconA hash.
#[derive(Clone, Debug)]
struct Parameters;

impl HashParameters for Parameters {
    const ROUNDS: usize = 12;
    const IV0: u64 = 0xee9398aadb67f03d;
    const IV1: u64 = 0x8bb21831c60f1002;
    const IV2: u64 = 0xb48a92db98d5da62;
    const IV3: u64 = 0x43189921b8f8e3e8;
    const IV4: u64 = 0x348fa5c9d525e140;
}

/// Parameters for AsconA hash.
#[derive(Clone, Debug)]
struct ParametersA;

impl HashParameters for ParametersA {
    const ROUNDS: usize = 8;
    const IV0: u64 = 0x01470194fc6528a6;
    const IV1: u64 = 0x738ec38ac0adffa7;
    const IV2: u64 = 0x2ec8e3296c76384c;
    const IV3: u64 = 0xd6f6a54d7f52377d;
    const IV4: u64 = 0xa13c42a223be8d87;
}

#[derive(Clone, Debug)]
struct ParametersXof;

impl HashParameters for ParametersXof {
    const ROUNDS: usize = 12;
    const IV0: u64 = 0xb57e273b814cd416;
    const IV1: u64 = 0x2b51042562ae2420;
    const IV2: u64 = 0x66a3a7768ddf2218;
    const IV3: u64 = 0x5aad0a7a8153650c;
    const IV4: u64 = 0x4f3e0e32539493b6;
}

#[derive(Clone, Debug)]
struct ParametersAXof;

impl HashParameters for ParametersAXof {
    const ROUNDS: usize = 8;
    const IV0: u64 = 0x44906568b77b9832;
    const IV1: u64 = 0xcd8d6cae53455532;
    const IV2: u64 = 0xf7b5212756422129;
    const IV3: u64 = 0x246885e1de0d225b;
    const IV4: u64 = 0xa8cb5ce33449973f;
}

#[derive(Clone, Debug)]
struct HashCore<P: HashParameters> {
    state: State,
    phantom: PhantomData<P>,
}

impl<P: HashParameters> HashCore<P> {
    fn absorb_block(&mut self, block: &[u8; 8]) {
        self.state[0] ^= u64::from_be_bytes(*block);
        self.permute_state();
    }

    fn absorb_last_block(&mut self, block: &[u8]) {
        debug_assert!(block.len() < 8);

        let len = block.len();
        if len > 0 {
            let mut tmp = [0u8; 8];
            tmp[0..len].copy_from_slice(block);
            self.state[0] ^= u64::from_be_bytes(tmp);
        }
        self.state[0] ^= pad(len);
        self.state.permute_12();
    }

    // for fixed-sized output
    fn squeeze(&mut self, mut block: &mut [u8]) {
        debug_assert_eq!(block.len() % 8, 0);

        while block.len() > 8 {
            block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
            self.permute_state();
            block = &mut block[8..];
        }
        block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
    }

    // for XOF output
    fn squeeze_block(&mut self) -> [u8; 8] {
        let ret = u64::to_be_bytes(self.state[0]);
        self.permute_state();
        ret
    }

    #[inline(always)]
    fn permute_state(&mut self) {
        if P::ROUNDS == 12 {
            self.state.permute_12();
        } else if P::ROUNDS == 8 {
            self.state.permute_8();
        } else if P::ROUNDS == 6 {
            self.state.permute_6();
        }
    }
}

impl<P: HashParameters> Default for HashCore<P> {
    fn default() -> Self {
        Self {
            state: State::new(P::IV0, P::IV1, P::IV2, P::IV3, P::IV4),
            phantom: PhantomData,
        }
    }
}

/// Ascon hash implementation
#[derive(Clone, Debug, Default)]
pub struct AsconCore {
    state: HashCore<Parameters>,
}

impl HashMarker for AsconCore {}

impl BlockSizeUser for AsconCore {
    type BlockSize = U8;
}

impl BufferKindUser for AsconCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for AsconCore {
    type OutputSize = U32;
}

impl UpdateCore for AsconCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state.absorb_block(block.as_ref());
        }
    }
}

impl FixedOutputCore for AsconCore {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        debug_assert!(buffer.get_pos() < 8);
        self.state
            .absorb_last_block(&buffer.get_data()[..buffer.get_pos()]);
        self.state.squeeze(out);
    }
}

impl Reset for AsconCore {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for AsconCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AsconHash")
    }
}

/// Ascon hash implementation
#[derive(Clone, Debug, Default)]
pub struct AsconACore {
    state: HashCore<ParametersA>,
}

impl HashMarker for AsconACore {}

impl BlockSizeUser for AsconACore {
    type BlockSize = U8;
}

impl BufferKindUser for AsconACore {
    type BufferKind = Eager;
}

impl OutputSizeUser for AsconACore {
    type OutputSize = U32;
}

impl UpdateCore for AsconACore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state.absorb_block(block.as_ref());
        }
    }
}

impl FixedOutputCore for AsconACore {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        debug_assert!(buffer.get_pos() < 8);
        self.state
            .absorb_last_block(&buffer.get_data()[..buffer.get_pos()]);
        self.state.squeeze(out);
    }
}

impl Reset for AsconACore {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for AsconACore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AsconAHash")
    }
}

/// Ascon XOF
#[derive(Clone, Debug, Default)]
pub struct AsconXofCore {
    state: HashCore<ParametersXof>,
}

impl HashMarker for AsconXofCore {}

impl BlockSizeUser for AsconXofCore {
    type BlockSize = U8;
}

impl BufferKindUser for AsconXofCore {
    type BufferKind = Eager;
}

impl UpdateCore for AsconXofCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state.absorb_block(block.as_ref());
        }
    }
}

/// Reader for XOF output
#[derive(Clone, Debug)]
pub struct AsconXofReaderCore {
    hasher: HashCore<ParametersXof>,
}

impl BlockSizeUser for AsconXofReaderCore {
    type BlockSize = U8;
}

impl XofReaderCore for AsconXofReaderCore {
    fn read_block(&mut self) -> Block<Self> {
        self.hasher.squeeze_block().into()
    }
}

impl ExtendableOutputCore for AsconXofCore {
    type ReaderCore = AsconXofReaderCore;

    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        debug_assert!(buffer.get_pos() < 8);
        self.state
            .absorb_last_block(&buffer.get_data()[..buffer.get_pos()]);
        Self::ReaderCore {
            hasher: self.state.clone(),
        }
    }
}

impl Reset for AsconXofCore {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for AsconXofCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AsconXOF")
    }
}

/// AsconA XOF
#[derive(Clone, Debug, Default)]
pub struct AsconAXofCore {
    state: HashCore<ParametersAXof>,
}

impl HashMarker for AsconAXofCore {}

impl BlockSizeUser for AsconAXofCore {
    type BlockSize = U8;
}

impl BufferKindUser for AsconAXofCore {
    type BufferKind = Eager;
}

impl UpdateCore for AsconAXofCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state.absorb_block(block.as_ref());
        }
    }
}

/// Reader for XOF output
#[derive(Clone, Debug)]
pub struct AsconAXofReaderCore {
    hasher: HashCore<ParametersAXof>,
}

impl BlockSizeUser for AsconAXofReaderCore {
    type BlockSize = U8;
}

impl XofReaderCore for AsconAXofReaderCore {
    fn read_block(&mut self) -> Block<Self> {
        self.hasher.squeeze_block().into()
    }
}

impl ExtendableOutputCore for AsconAXofCore {
    type ReaderCore = AsconAXofReaderCore;

    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        debug_assert!(buffer.get_pos() < 8);
        self.state
            .absorb_last_block(&buffer.get_data()[..buffer.get_pos()]);
        Self::ReaderCore {
            hasher: self.state.clone(),
        }
    }
}

impl Reset for AsconAXofCore {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for AsconAXofCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AsconAXOF")
    }
}

/// Ascon hash
///
/// ```
/// use ascon_hash::{AsconHash, Digest};
///
/// let mut hasher = AsconHash::new();
/// hasher.update(b"some bytes");
/// let digest = hasher.finalize();
/// assert_eq!(&digest[..], b"\xb7\x42\xca\x75\xe5\x70\x38\x75\x70\x59\xcc\xcc\x68\x74\x71\x4f\x9d\xbd\x7f\xc5\x92\x4a\x7d\xf4\xe3\x16\x59\x4f\xd1\x42\x6c\xa8");
/// ```
pub type AsconHash = CoreWrapper<AsconCore>;
/// AsconA hash
///
/// ```
/// use ascon_hash::{AsconAHash, Digest};
///
/// let mut hasher = AsconAHash::new();
/// hasher.update(b"some bytes");
/// let digest = hasher.finalize();
/// assert_eq!(&digest[..], b"\x1d\x1a\xc8\x74\x4a\x4a\x05\x81\x33\x7d\x5a\xf2\x78\xc2\x55\x88\xe1\xa3\xdd\x2d\x86\x73\x07\x64\x26\x53\xdc\xa4\x45\xf5\x5c\x2a");
/// ```
pub type AsconAHash = CoreWrapper<AsconACore>;
/// AsconXof
///
/// ```
/// use ascon_hash::{AsconXof, ExtendableOutput, Update, XofReader};
///
/// let mut xof = AsconXof::default();
/// xof.update(b"some bytes");
/// let mut reader = xof.finalize_xof();
/// let mut dst = [0u8; 5];
/// reader.read(&mut dst);
/// assert_eq!(&dst, b"\xc2\x19\x72\xfd\xe9");
/// ```
pub type AsconXof = CoreWrapper<AsconXofCore>;
/// Reader for AsconXof output
pub type AsconAXofReader = XofReaderCoreWrapper<AsconAXofReaderCore>;
/// AsconAXof
///
/// ```
/// use ascon_hash::{AsconAXof, ExtendableOutput, Update, XofReader};
///
/// let mut xof = AsconAXof::default();
/// xof.update(b"some bytes");
/// let mut reader = xof.finalize_xof();
/// let mut dst = [0u8; 5];
/// reader.read(&mut dst);
/// assert_eq!(&dst, b"\xb8\xd6\xbd\xf0\xa7");
/// ```
pub type AsconAXof = CoreWrapper<AsconAXofCore>;
/// Reader for AsconAXof output
pub type AsconXofReader = XofReaderCoreWrapper<AsconAXofReaderCore>;

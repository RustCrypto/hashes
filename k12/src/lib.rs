#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, unreachable_pub)]

pub use digest;

use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, Reset, Update,
    block_api::{AlgorithmName, BlockSizeUser},
    block_buffer::BlockSizes,
    consts::{U16, U32, U136, U168},
};

mod consts;
/// Customized variants.
pub mod custom;
/// Implementation of TurboSHAKE specialized for computation of chaining values on full nodes
mod node_turbo_shake;
/// Implementation of the XOF reader
mod reader;
/// Vendored implementation of TurboSHAKE
mod turbo_shake;
/// Implementation of the update closure generic over Keccak backend
mod update;
/// Utility functions
mod utils;

pub use custom::*;
pub use reader::KtReader;

use consts::{CHUNK_SIZE_U64, FINAL_NODE_DS, INTERMEDIATE_NODE_DS, ROUNDS, SINGLE_NODE_DS};
use turbo_shake::TurboShake;
use utils::{copy_cv, length_encode};

/// KangarooTwelve hasher generic over rate.
///
/// Only `U136` and `U168` rates are supported which correspond to KT256 and KT128 respectively.
/// Using other rates will result in a compilation error.
#[derive(Clone)]
pub struct Kt<Rate: BlockSizes> {
    accum_tshk: TurboShake<Rate>,
    node_tshk: TurboShake<Rate>,
    consumed_len: u64,
    keccak: keccak::Keccak,
}

impl<Rate: BlockSizes> Default for Kt<Rate> {
    #[inline]
    fn default() -> Self {
        const { assert!(matches!(Rate::USIZE, 136 | 168)) }
        Self {
            accum_tshk: Default::default(),
            node_tshk: Default::default(),
            consumed_len: 0,
            keccak: Default::default(),
        }
    }
}

impl<Rate: BlockSizes> fmt::Debug for Kt<Rate> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Kt{} {{ ... }}", 4 * (200 - Rate::USIZE))
    }
}

impl<Rate: BlockSizes> AlgorithmName for Kt<Rate> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KT{}", 4 * (200 - Rate::USIZE))
    }
}

impl<Rate: BlockSizes> HashMarker for Kt<Rate> {}

impl<Rate: BlockSizes> BlockSizeUser for Kt<Rate> {
    type BlockSize = Rate;
}

impl<Rate: BlockSizes> Update for Kt<Rate> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        let keccak = self.keccak;
        let closure = update::Closure::<'_, Rate> { data, kt: self };
        keccak.with_backend(closure);
    }
}

impl<Rate: BlockSizes> Reset for Kt<Rate> {
    #[inline]
    fn reset(&mut self) {
        self.accum_tshk.reset();
        self.node_tshk.reset();
        self.consumed_len = 0;
    }
}

impl<Rate: BlockSizes> Kt<Rate> {
    #[inline]
    fn raw_finalize(&mut self) -> KtReader<Rate> {
        let keccak = self.keccak;

        keccak.with_p1600::<ROUNDS>(|p1600| {
            if self.consumed_len <= CHUNK_SIZE_U64 {
                self.accum_tshk.finalize::<SINGLE_NODE_DS>(p1600);
            } else {
                let nodes_len = (self.consumed_len - 1) / CHUNK_SIZE_U64;
                let partial_node_len = self.consumed_len % CHUNK_SIZE_U64;

                if partial_node_len != 0 {
                    self.node_tshk.finalize::<INTERMEDIATE_NODE_DS>(p1600);
                    // TODO: this should be [0u8; {200 - Rate}]
                    let cv_dst = &mut [0u8; 200][..200 - Rate::USIZE];
                    copy_cv(self.node_tshk.state(), cv_dst);
                    self.accum_tshk.absorb(p1600, cv_dst);
                }

                length_encode(nodes_len, |enc_len| self.accum_tshk.absorb(p1600, enc_len));
                self.accum_tshk.absorb(p1600, b"\xFF\xFF");
                self.accum_tshk.finalize::<FINAL_NODE_DS>(p1600);
            };
        });

        KtReader {
            state: *self.accum_tshk.state(),
            buffer: Default::default(),
            keccak,
        }
    }
}

impl<Rate: BlockSizes> ExtendableOutput for Kt<Rate> {
    type Reader = KtReader<Rate>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.update(&[0x00]);
        self.raw_finalize()
    }
}

impl<Rate: BlockSizes> ExtendableOutputReset for Kt<Rate> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.update(&[0x00]);
        let reader = self.raw_finalize();
        self.reset();
        reader
    }
}

impl<Rate: BlockSizes> Drop for Kt<Rate> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.consumed_len.zeroize();
            // `accum_tshk` and `node_tshk` are zeroized by `Drop`
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate: BlockSizes> digest::zeroize::ZeroizeOnDrop for Kt<Rate> {}

/// KT128 hasher.
pub type Kt128 = Kt<U168>;
/// KT256 hasher.
pub type Kt256 = Kt<U136>;

/// KT128 XOF reader.
pub type Kt128Reader = KtReader<U168>;
/// KT256 XOF reader.
pub type Kt256Reader = KtReader<U136>;

impl CollisionResistance for Kt128 {
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-7-7
    type CollisionResistance = U16;
}

impl CollisionResistance for Kt256 {
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-7-8
    type CollisionResistance = U32;
}

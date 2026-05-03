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
    array::ArraySize,
    common::{AlgorithmName, BlockSizeUser},
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

use consts::{CHUNK_SIZE_U64, FINAL_NODE_DS, ROUNDS, SINGLE_NODE_DS};
use turbo_shake::TurboShake;
use utils::length_encode;

/// KangarooTwelve hasher generic over rate.
///
/// Only `U136` and `U168` rates are supported which correspond to KT256 and KT128 respectively.
/// Using other rates will result in a compilation error.
#[derive(Clone)]
pub struct Kt<Rate: ArraySize> {
    accum_tshk: TurboShake<Rate>,
    node_tshk: TurboShake<Rate>,
    consumed_len: u64,
    keccak: keccak::Keccak,
}

impl<Rate: ArraySize> Default for Kt<Rate> {
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

impl<Rate: ArraySize> fmt::Debug for Kt<Rate> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Kt{} {{ ... }}", 4 * (200 - Rate::USIZE))
    }
}

impl<Rate: ArraySize> AlgorithmName for Kt<Rate> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KT{}", 4 * (200 - Rate::USIZE))
    }
}

impl<Rate: ArraySize> HashMarker for Kt<Rate> {}

impl<Rate: ArraySize> BlockSizeUser for Kt<Rate> {
    type BlockSize = Rate;
}

impl<Rate: ArraySize> Update for Kt<Rate> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        let keccak = self.keccak;
        let closure = update::Closure::<'_, Rate> { data, kt: self };
        keccak.with_backend(closure);
    }
}

impl<Rate: ArraySize> Reset for Kt<Rate> {
    #[inline]
    fn reset(&mut self) {
        self.accum_tshk.reset();
        self.node_tshk.reset();
        self.consumed_len = 0;
    }
}

impl<Rate: ArraySize> Kt<Rate> {
    #[inline]
    fn raw_finalize(&mut self) -> KtReader<Rate> {
        let keccak = self.keccak;

        if self.consumed_len <= CHUNK_SIZE_U64 {
            self.accum_tshk.pad::<SINGLE_NODE_DS>();
        } else {
            keccak.with_p1600::<ROUNDS>(|p1600| {
                let nodes_len = (self.consumed_len - 1) / CHUNK_SIZE_U64;
                let partial_node_len = self.consumed_len % CHUNK_SIZE_U64;

                if partial_node_len != 0 {
                    // TODO: this should be [0u8; {200 - Rate}]
                    let cv_dst = &mut [0u8; 200][..200 - Rate::USIZE];
                    self.node_tshk.finalize_node(p1600, cv_dst);
                    self.accum_tshk.absorb(p1600, cv_dst);
                }

                length_encode(nodes_len, |enc_len| self.accum_tshk.absorb(p1600, enc_len));
                self.accum_tshk.absorb(p1600, b"\xFF\xFF");
                self.accum_tshk.pad::<FINAL_NODE_DS>();
            });
        };

        KtReader::new(self.accum_tshk.state(), keccak)
    }
}

impl<Rate: ArraySize> ExtendableOutput for Kt<Rate> {
    type Reader = KtReader<Rate>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.update(&[0x00]);
        self.raw_finalize()
    }
}

impl<Rate: ArraySize> ExtendableOutputReset for Kt<Rate> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.update(&[0x00]);
        let reader = self.raw_finalize();
        self.reset();
        reader
    }
}

impl<Rate: ArraySize> Drop for Kt<Rate> {
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
impl<Rate: ArraySize> digest::zeroize::ZeroizeOnDrop for Kt<Rate> {}

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

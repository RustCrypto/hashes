extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use digest::{
    CollisionResistance, CustomizedInit, ExtendableOutput, ExtendableOutputReset, HashMarker,
    Reset, Update,
    common::{AlgorithmName, BlockSizeUser},
    consts::{U16, U32, U136, U168},
};

use crate::{Kt, KtReader, utils::length_encode};

/// Customized KangarooTwelve hasher generic over rate with owned customization string.
#[derive(Clone)]
pub struct CustomKt<const RATE: usize> {
    customization: Vec<u8>,
    inner: Kt<RATE>,
}

impl<const RATE: usize> CustomizedInit for CustomKt<RATE> {
    #[inline]
    fn new_customized(customization: &[u8]) -> Self {
        let len = u64::try_from(customization.len()).expect("length should always fit into `u64`");
        let mut buf = Vec::new();
        length_encode(len, |enc_len| {
            buf = Vec::with_capacity(customization.len() + enc_len.len());
            buf.extend_from_slice(customization);
            buf.extend_from_slice(enc_len);
        });

        Self {
            customization: buf,
            inner: Default::default(),
        }
    }
}

impl<const RATE: usize> Default for CustomKt<RATE> {
    #[inline]
    fn default() -> Self {
        Self::new_customized(&[])
    }
}

impl<const RATE: usize> fmt::Debug for CustomKt<RATE> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "CustomKt{} {{ ... }}", 4 * (200 - RATE))
    }
}

impl<const RATE: usize> AlgorithmName for CustomKt<RATE> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Kt::<RATE>::write_alg_name(f)
    }
}

impl<const RATE: usize> HashMarker for CustomKt<RATE> {}

impl<const RATE: usize> Update for CustomKt<RATE> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
}

impl<const RATE: usize> Reset for CustomKt<RATE> {
    #[inline]
    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<const RATE: usize> ExtendableOutput for CustomKt<RATE> {
    type Reader = KtReader<RATE>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.inner.update(&self.customization);
        self.inner.raw_finalize()
    }
}

impl<const RATE: usize> ExtendableOutputReset for CustomKt<RATE> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.inner.update(&self.customization);
        let reader = self.inner.raw_finalize();
        self.inner.reset();
        reader
    }
}

impl<const RATE: usize> Drop for CustomKt<RATE> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.customization.zeroize();
            // `inner` is zeroized by `Drop`
        }
    }
}

#[cfg(feature = "zeroize")]
impl<const RATE: usize> digest::zeroize::ZeroizeOnDrop for CustomKt<RATE> {}

/// Customized KT128 hasher with owned customization string.
pub type CustomKt128 = CustomKt<168>;
/// Customized KT256 hasher with owned customization string.
pub type CustomKt256 = CustomKt<136>;

impl CollisionResistance for CustomKt128 {
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-7-7
    type CollisionResistance = U16;
}

impl CollisionResistance for CustomKt256 {
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-7-8
    type CollisionResistance = U32;
}

impl BlockSizeUser for CustomKt128 {
    type BlockSize = U168;
}

impl BlockSizeUser for CustomKt256 {
    type BlockSize = U136;
}

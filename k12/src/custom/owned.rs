extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use digest::{
    CollisionResistance, CustomizedInit, ExtendableOutput, ExtendableOutputReset, HashMarker,
    Reset, Update,
    block_buffer::BlockSizes,
    common::{AlgorithmName, BlockSizeUser},
    consts::{U16, U32, U136, U168},
};

use crate::{Kt, KtReader, utils::length_encode};

/// Customized KangarooTwelve hasher generic over rate with owned customization string.
#[derive(Clone)]
pub struct CustomKt<Rate: BlockSizes> {
    customization: Vec<u8>,
    inner: Kt<Rate>,
}

impl<Rate: BlockSizes> CustomizedInit for CustomKt<Rate> {
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

impl<Rate: BlockSizes> Default for CustomKt<Rate> {
    #[inline]
    fn default() -> Self {
        Self::new_customized(&[])
    }
}

impl<Rate: BlockSizes> fmt::Debug for CustomKt<Rate> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "CustomKt{} {{ ... }}", 4 * (200 - Rate::USIZE))
    }
}

impl<Rate: BlockSizes> AlgorithmName for CustomKt<Rate> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Kt::<Rate>::write_alg_name(f)
    }
}

impl<Rate: BlockSizes> HashMarker for CustomKt<Rate> {}

impl<Rate: BlockSizes> BlockSizeUser for CustomKt<Rate> {
    type BlockSize = Rate;
}

impl<Rate: BlockSizes> Update for CustomKt<Rate> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
}

impl<Rate: BlockSizes> Reset for CustomKt<Rate> {
    #[inline]
    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<Rate: BlockSizes> ExtendableOutput for CustomKt<Rate> {
    type Reader = KtReader<Rate>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.inner.update(&self.customization);
        self.inner.raw_finalize()
    }
}

impl<Rate: BlockSizes> ExtendableOutputReset for CustomKt<Rate> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.inner.update(&self.customization);
        let reader = self.inner.raw_finalize();
        self.inner.reset();
        reader
    }
}

impl<Rate: BlockSizes> Drop for CustomKt<Rate> {
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
impl<Rate: BlockSizes> digest::zeroize::ZeroizeOnDrop for CustomKt<Rate> {}

/// Customized KT128 hasher with owned customization string.
pub type CustomKt128 = CustomKt<U168>;
/// Customized KT256 hasher with owned customization string.
pub type CustomKt256 = CustomKt<U136>;

impl CollisionResistance for CustomKt128 {
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-7-7
    type CollisionResistance = U16;
}

impl CollisionResistance for CustomKt256 {
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-7-8
    type CollisionResistance = U32;
}

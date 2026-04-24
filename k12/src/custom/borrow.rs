use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, Reset, Update,
    block_buffer::BlockSizes,
    common::{AlgorithmName, BlockSizeUser},
    consts::{U16, U32, U136, U168},
};

use crate::{Kt, KtReader, utils::length_encode};

/// Customized KangarooTwelve hasher generic over rate with borrrowed customization string.
#[derive(Clone)]
pub struct CustomRefKt<'a, Rate: BlockSizes> {
    customization: &'a [u8],
    inner: Kt<Rate>,
}

impl<'a, Rate: BlockSizes> CustomRefKt<'a, Rate> {
    /// Create new customized KangarooTwelve hasher with borrrowed customization string.
    ///
    /// Note that this is an inherent method and `CustomRefKt` does not implement
    /// the [`CustomizedInit`][digest::CustomizedInit] trait.
    #[inline]
    pub fn new_customized(customization: &'a [u8]) -> Self {
        Self {
            customization,
            inner: Default::default(),
        }
    }
}

impl<Rate: BlockSizes> Default for CustomRefKt<'static, Rate> {
    #[inline]
    fn default() -> Self {
        Self::new_customized(&[])
    }
}

impl<Rate: BlockSizes> fmt::Debug for CustomRefKt<'_, Rate> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "CustomKt{} {{ ... }}", 4 * (200 - Rate::USIZE))
    }
}

impl<Rate: BlockSizes> AlgorithmName for CustomRefKt<'_, Rate> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Kt::<Rate>::write_alg_name(f)
    }
}

impl<Rate: BlockSizes> HashMarker for CustomRefKt<'_, Rate> {}

impl<Rate: BlockSizes> BlockSizeUser for CustomRefKt<'_, Rate> {
    type BlockSize = Rate;
}

impl<Rate: BlockSizes> Update for CustomRefKt<'_, Rate> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
}

impl<Rate: BlockSizes> Reset for CustomRefKt<'_, Rate> {
    #[inline]
    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<Rate: BlockSizes> CustomRefKt<'_, Rate> {
    fn absorb_customization(&mut self) {
        self.inner.update(self.customization);
        let len = u64::try_from(self.customization.len()).expect("length always fits into `u64`");
        length_encode(len, |enc_len| self.inner.update(enc_len));
    }
}

impl<Rate: BlockSizes> ExtendableOutput for CustomRefKt<'_, Rate> {
    type Reader = KtReader<Rate>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.absorb_customization();
        self.inner.raw_finalize()
    }
}

impl<Rate: BlockSizes> ExtendableOutputReset for CustomRefKt<'_, Rate> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.absorb_customization();
        let reader = self.inner.raw_finalize();
        self.inner.reset();
        reader
    }
}

// `inner` is zeroized by `Drop` and `customization` can not be zeroized
#[cfg(feature = "zeroize")]
impl<Rate: BlockSizes> digest::zeroize::ZeroizeOnDrop for CustomRefKt<'_, Rate> {}

/// Customized KT128 hasher with borrowed customization string.
pub type CustomRefKt128<'a> = CustomRefKt<'a, U168>;
/// Customized KT256 hasher with borrowed customization string.
pub type CustomRefKt256<'a> = CustomRefKt<'a, U136>;

impl CollisionResistance for CustomRefKt128<'_> {
    type CollisionResistance = U16;
}

impl CollisionResistance for CustomRefKt256<'_> {
    type CollisionResistance = U32;
}

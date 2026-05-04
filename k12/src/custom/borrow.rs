use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, Reset, Update,
    common::{AlgorithmName, BlockSizeUser},
    consts::{U16, U32, U136, U168},
};

use crate::{Kt, KtReader, utils::length_encode};

/// Customized KangarooTwelve hasher generic over rate with borrrowed customization string.
#[derive(Clone)]
pub struct CustomRefKt<'a, const RATE: usize> {
    customization: &'a [u8],
    inner: Kt<RATE>,
}

impl<'a, const RATE: usize> CustomRefKt<'a, RATE> {
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

impl<const RATE: usize> Default for CustomRefKt<'static, RATE> {
    #[inline]
    fn default() -> Self {
        Self::new_customized(&[])
    }
}

impl<const RATE: usize> fmt::Debug for CustomRefKt<'_, RATE> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "CustomKt{} {{ ... }}", 4 * (200 - RATE))
    }
}

impl<const RATE: usize> AlgorithmName for CustomRefKt<'_, RATE> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Kt::<RATE>::write_alg_name(f)
    }
}

impl<const RATE: usize> HashMarker for CustomRefKt<'_, RATE> {}

impl<const RATE: usize> Update for CustomRefKt<'_, RATE> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
}

impl<const RATE: usize> Reset for CustomRefKt<'_, RATE> {
    #[inline]
    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl<const RATE: usize> CustomRefKt<'_, RATE> {
    fn absorb_customization(&mut self) {
        self.inner.update(self.customization);
        let len = u64::try_from(self.customization.len()).expect("length always fits into `u64`");
        length_encode(len, |enc_len| self.inner.update(enc_len));
    }
}

impl<const RATE: usize> ExtendableOutput for CustomRefKt<'_, RATE> {
    type Reader = KtReader<RATE>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.absorb_customization();
        self.inner.raw_finalize()
    }
}

impl<const RATE: usize> ExtendableOutputReset for CustomRefKt<'_, RATE> {
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
impl<const RATE: usize> digest::zeroize::ZeroizeOnDrop for CustomRefKt<'_, RATE> {}

/// Customized KT128 hasher with borrowed customization string.
pub type CustomRefKt128<'a> = CustomRefKt<'a, 168>;
/// Customized KT256 hasher with borrowed customization string.
pub type CustomRefKt256<'a> = CustomRefKt<'a, 136>;

impl CollisionResistance for CustomRefKt128<'_> {
    type CollisionResistance = U16;
}

impl CollisionResistance for CustomRefKt256<'_> {
    type CollisionResistance = U32;
}

impl BlockSizeUser for CustomRefKt128<'_> {
    type BlockSize = U168;
}

impl BlockSizeUser for CustomRefKt256<'_> {
    type BlockSize = U136;
}

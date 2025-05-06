use crate::{Sha3HasherCore, Sha3ReaderCore};
use core::fmt;
use digest::{
    ExtendableOutput, ExtendableOutputReset, HashMarker, Update,
    consts::{U0, U136, U168},
    core_api::{AlgorithmName, BlockSizeUser, CoreWrapper, Reset, XofReaderCoreWrapper},
};

const TURBO_SHAKE_ROUND_COUNT: usize = 12;

macro_rules! impl_turbo_shake {
    (
        $name:ident, $reader_name:ident, $rate:ty, $alg_name:expr
    ) => {
        #[doc = $alg_name]
        #[doc = " hasher."]
        #[derive(Clone)]
        pub struct $name<const DS: u8>(
            CoreWrapper<Sha3HasherCore<$rate, U0, DS, TURBO_SHAKE_ROUND_COUNT>>,
        );

        impl<const DS: u8> Default for $name<DS> {
            #[inline]
            fn default() -> Self {
                assert!((0x01..=0x7F).contains(&DS), "invalid domain separator");
                Self(Default::default())
            }
        }

        impl<const DS: u8> HashMarker for $name<DS> {}

        impl<const DS: u8> BlockSizeUser for $name<DS> {
            type BlockSize = $rate;
        }

        impl<const DS: u8> Update for $name<DS> {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.update(data)
            }
        }

        #[doc = $alg_name]
        #[doc = " XOF reader."]
        pub type $reader_name =
            XofReaderCoreWrapper<Sha3ReaderCore<$rate, TURBO_SHAKE_ROUND_COUNT>>;

        impl<const DS: u8> ExtendableOutput for $name<DS> {
            type Reader = $reader_name;

            #[inline]
            fn finalize_xof(self) -> Self::Reader {
                self.0.finalize_xof()
            }
        }

        impl<const DS: u8> ExtendableOutputReset for $name<DS> {
            #[inline]
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                self.0.finalize_xof_reset()
            }
        }

        impl<const DS: u8> Reset for $name<DS> {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl<const DS: u8> AlgorithmName for $name<DS> {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($alg_name))
            }
        }

        impl<const DS: u8> fmt::Debug for $name<DS> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg(feature = "zeroize")]
        impl<const DS: u8> digest::zeroize::ZeroizeOnDrop for $name<DS> {}
    };
}

impl_turbo_shake!(TurboShake128, TurboShake128Reader, U168, "TurboSHAKE128");
impl_turbo_shake!(TurboShake256, TurboShake256Reader, U136, "TurboSHAKE256");

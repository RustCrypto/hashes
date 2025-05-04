use crate::{Skein256Core, Skein512Core, Skein1024Core};
use core::fmt;
use digest::{
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
    array::ArraySize,
    core_api::{AlgorithmName, BlockSizeUser, CoreWrapper},
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
};

macro_rules! newtype {
    ($name:ident<$n:ident>, $inner:ty, $alg_name:literal) => {
        #[doc = $alg_name]
        #[doc = " hasher generic over output size"]
        pub struct $name<$n: ArraySize>(CoreWrapper<$inner>);

        impl<$n: ArraySize> fmt::Debug for $name<$n> {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}<{}> {{ ... }}", stringify!($name), N::USIZE)
            }
        }

        impl<$n: ArraySize> AlgorithmName for $name<$n> {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}-{}", $alg_name, N::USIZE)
            }
        }

        impl<$n: ArraySize> Clone for $name<$n> {
            #[inline]
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<$n: ArraySize> Default for $name<$n> {
            #[inline]
            fn default() -> Self {
                Self(Default::default())
            }
        }

        impl<$n: ArraySize> Reset for $name<$n> {
            #[inline]
            fn reset(&mut self) {
                Reset::reset(&mut self.0);
            }
        }

        impl<$n: ArraySize> Update for $name<$n> {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                Update::update(&mut self.0, data);
            }
        }

        impl<$n: ArraySize> FixedOutput for $name<$n> {
            #[inline]
            fn finalize_into(self, out: &mut Output<Self>) {
                FixedOutput::finalize_into(self.0, out);
            }
        }

        impl<$n: ArraySize> FixedOutputReset for $name<$n> {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                FixedOutputReset::finalize_into_reset(&mut self.0, out);
            }
        }

        impl<$n: ArraySize> HashMarker for $name<$n> {}

        impl<$n: ArraySize> BlockSizeUser for $name<$n> {
            type BlockSize = <$inner as BlockSizeUser>::BlockSize;
        }

        impl<$n: ArraySize> OutputSizeUser for $name<$n> {
            type OutputSize = <$inner as OutputSizeUser>::OutputSize;
        }

        impl<$n: ArraySize> SerializableState for $name<$n> {
            type SerializedStateSize =
                <CoreWrapper<$inner> as SerializableState>::SerializedStateSize;

            #[inline]
            fn serialize(&self) -> SerializedState<Self> {
                self.0.serialize()
            }

            #[inline]
            fn deserialize(
                serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                SerializableState::deserialize(serialized_state).map(Self)
            }
        }
    };
}

newtype!(Skein256<N>, Skein256Core<N>, "Skein-256");
newtype!(Skein512<N>, Skein512Core<N>, "Skein-512");
newtype!(Skein1024<N>, Skein1024Core<N>, "Skein-1024");

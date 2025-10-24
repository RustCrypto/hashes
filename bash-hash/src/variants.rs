use digest::{array::ArraySize, crypto_common::BlockSizes, typenum};

/// Sealed trait to prevent external implementations.
pub trait Sealed {}

/// Trait implemented for output sizes supported by `bash-hash`.
///
/// Supported output sizes form the following list: U4, U8, ..., U60, U64.
pub trait OutputSize: ArraySize + Sealed {
    /// Block size in bytes computed as `192 - 2 * OutputSize`.
    type BlockSize: BlockSizes;
}

macro_rules! impl_sizes {
    ($($variant:ident, $block_size:ident;)*) => {
        $(
            impl Sealed for typenum::$variant {}

            impl OutputSize for typenum::$variant {
                type BlockSize = typenum::$block_size;
            }
        )*
    };
}

impl_sizes!(
    U4,  U184;
    U8,  U176;
    U12, U168;
    U16, U160;
    U20, U152;
    U24, U144;
    U28, U136;
    U32, U128;
    U36, U120;
    U40, U112;
    U44, U104;
    U48, U96;
    U52, U88;
    U56, U80;
    U60, U72;
    U64, U64;
);

use digest::generic_array::typenum::{U16, U32, U64};
use consts::BLAKE2B_IV;

blake2_impl!(VarBlake2b, FixedBlake2b, u64, u64x4, U64,
    32, 24, 16, 63, BLAKE2B_IV,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
);

/// Blake2b with 128 bit output
pub type Blake2b128 = FixedBlake2b<U16>;
/// Blake2b with 256 bit output
pub type Blake2b256 = FixedBlake2b<U32>;
/// Blake2b with 512 bit output
pub type Blake2b512 = FixedBlake2b<U64>;
/// Blake2b with 512 bit output
pub type Blake2b = FixedBlake2b<U64>;

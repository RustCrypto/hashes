use digest::generic_array::typenum::{U16, U32};
use consts::BLAKE2S_IV;

blake2_impl!(VarBlake2s, FixedBlake2s, u32, u32x4, U32,
    16, 12, 8, 7, BLAKE2S_IV,
    "Blake2s instance with a variable output.",
    "Blake2s instance with a fixed output.",
);

/// Blake2s with 128bit output
pub type Blake2s128 = FixedBlake2s<U16>;
/// Blake2s with 256bit output
pub type Blake2s256 = FixedBlake2s<U32>;

pub type Blake2s = FixedBlake2s<U32>;

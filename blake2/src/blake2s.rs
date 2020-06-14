use digest::generic_array::typenum::{U32, U64};

blake2_impl!(
    VarBlake2s,
    Blake2s,
    blake2s_simd::State,
    blake2s_simd::Params,
    U64,
    U32,
    U32,
    "Blake2s instance with a variable output.",
    "Blake2s instance with a fixed output.",
);

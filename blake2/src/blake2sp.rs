use digest::generic_array::typenum::{U32, U64};

blake2_impl!(
    VarBlake2sp,
    Blake2sp,
    blake2s_simd::blake2sp::State,
    blake2s_simd::blake2sp::Params,
    U64,
    U32,
    U32,
    "Blake2sp instance with a variable output.",
    "Blake2sp instance with a fixed output.",
);

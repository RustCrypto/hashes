use digest::generic_array::typenum::{U128, U64};

blake2_impl!(
    VarBlake2b,
    Blake2b,
    blake2b_simd::State,
    blake2b_simd::Params,
    U128,
    U64,
    U64,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
);

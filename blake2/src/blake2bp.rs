use digest::generic_array::typenum::{U128, U64};

blake2_impl!(
    VarBlake2bp,
    Blake2bp,
    blake2b_simd::blake2bp::State,
    blake2b_simd::blake2bp::Params,
    U128,
    U64,
    U64,
    "Blake2bp instance with a variable output.",
    "Blake2bp instance with a fixed output.",
);

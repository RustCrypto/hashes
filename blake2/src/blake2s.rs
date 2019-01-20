use digest::generic_array::typenum::U32;
use compressor_s::CompressorS;

blake2_impl!(VarBlake2s, Blake2s, CompressorS, u32, U32,
    "Blake2s instance with a variable output.",
    "Blake2s instance with a fixed output.",
);

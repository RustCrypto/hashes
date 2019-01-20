use digest::generic_array::typenum::U64;
use compressor_b::CompressorB;

blake2_impl!(VarBlake2b, Blake2b, CompressorB, u64, U64,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
);

use digest::generic_array::typenum::U64;
use compressor_b::{CompressorB, CompressorBBuilder};

blake2_p_impl!(VarBlake2bp, Blake2bp, CompressorB, CompressorBBuilder, u64, U64, 4,
    "Blake2bp instance with a variable output.",
    "Blake2bp instance with a fixed output.",
);

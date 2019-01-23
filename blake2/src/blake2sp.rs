use digest::generic_array::typenum::U32;
use compressor_s::{CompressorS, CompressorSBuilder};

blake2_p_impl!(VarBlake2sp, Blake2sp, CompressorS, CompressorSBuilder, u32, U32, 8,
    "Blake2sp instance with a variable output.",
    "Blake2sp instance with a fixed output.",
);

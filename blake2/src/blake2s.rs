use generic_array::typenum::U32;
use consts::BLAKE2S_IV;

blake2_impl!(Blake2s, u32, u32x4, U32,
    16, 12, 8, 7, BLAKE2S_IV);

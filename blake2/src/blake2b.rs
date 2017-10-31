use digest::generic_array::typenum::U64;
use consts::BLAKE2B_IV;

blake2_impl!(Blake2b, u64, u64x4, U64,
    32, 24, 16, 63, BLAKE2B_IV);

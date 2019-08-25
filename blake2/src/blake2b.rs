use digest::generic_array::typenum::{U64, U128};
use consts::BLAKE2B_IV;

blake2_impl!(VarBlake2b, Blake2b, u64, u64x4, U64, U128,
    32, 24, 16, 63, BLAKE2B_IV,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
);

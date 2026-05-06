use crate::BashPrgHash;
use digest::{
    CollisionResistance,
    consts::{U16, U24, U32},
};

/// `bash-prg-hash` with ℓ = 128 and d = 1
pub type BashPrgHash1281 = BashPrgHash<160, 1>;
/// `bash-prg-hash` with ℓ = 128 and d = 2
pub type BashPrgHash1282 = BashPrgHash<128, 2>;
/// `bash-prg-hash` with ℓ = 192 and d = 1
pub type BashPrgHash1921 = BashPrgHash<144, 1>;
/// `bash-prg-hash` with ℓ = 192 and d = 2
pub type BashPrgHash1922 = BashPrgHash<96, 2>;
/// `bash-prg-hash` with ℓ = 256 and d = 1
pub type BashPrgHash2561 = BashPrgHash<128, 1>;
/// `bash-prg-hash`` with ℓ = 256 and d = 2
pub type BashPrgHash2562 = BashPrgHash<64, 2>;

impl CollisionResistance for BashPrgHash1281 {
    type CollisionResistance = U16;
}
impl CollisionResistance for BashPrgHash1282 {
    type CollisionResistance = U16;
}
impl CollisionResistance for BashPrgHash1921 {
    type CollisionResistance = U24;
}
impl CollisionResistance for BashPrgHash1922 {
    type CollisionResistance = U24;
}
impl CollisionResistance for BashPrgHash2561 {
    type CollisionResistance = U32;
}
impl CollisionResistance for BashPrgHash2562 {
    type CollisionResistance = U32;
}

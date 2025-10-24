use digest::{
    array::ArraySize,
    crypto_common::BlockSizes,
    typenum::{U32, U48, U64, U96, U128},
};

/// Sealed trait to prevent external implementations.
pub trait Sealed: Clone {}

/// Trait for Bash hash variants.
pub trait Variant: Sealed {
    type BlockSize: ArraySize + BlockSizes;
    type OutputSize: ArraySize;
}

#[derive(Clone)]
/// `Bash256` variant with 256-bit output and 128-byte block size.
pub struct Bash256;
#[derive(Clone)]
/// `Bash384` variant with 384-bit output and 96-byte block size.
pub struct Bash384;
#[derive(Clone)]
/// `Bash512` variant with 512-bit output and 64-byte block size.
pub struct Bash512;

impl Sealed for Bash256 {}
impl Sealed for Bash384 {}
impl Sealed for Bash512 {}

impl Variant for Bash256 {
    type BlockSize = U128;
    type OutputSize = U32;
}

impl Variant for Bash384 {
    type BlockSize = U96;
    type OutputSize = U48;
}

impl Variant for Bash512 {
    type BlockSize = U64;
    type OutputSize = U64;
}

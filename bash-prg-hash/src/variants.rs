use digest::consts::U24;
use digest::typenum::{U1, U2, U16, U32, U64, U96, U128, U144, U160, Unsigned};
use sponge_cursor::array::ArraySize;

mod sealed {
    /// Sealed trait to prevent external implementations of SecurityLevel.
    pub trait SecurityLevel {}

    /// Sealed trait to prevent external implementations of Capacity.
    pub trait Capacity {}

    /// Sealed trait to prevent external implementations of RateParam.
    pub trait Rate {}
}

/// Security level trait for programmable algorithms.
///
/// Specified in Section 5.3 of STB 34.101.77-2020.
///
/// Standard levels: ℓ ∈ {128, 192, 256}.
///
/// Implemented for `U16`, `U24`, and `U32` from `digest::typenum`.
pub trait SecurityLevel: sealed::SecurityLevel + Unsigned {}

/// Capacity parameter for programmable algorithms.
///
/// Specified in Section 5.4 of STB 34.101.77-2020.
///
/// Capacity d ∈ {1, 2}.
///
/// Implemented for `U1` and `U2` from `digest::typenum`.
pub trait Capacity: sealed::Capacity + Unsigned {}

/// Rate parameter trait linking (SecurityLevel, Capacity) pairs to their rate.
///
/// Rate r = 192 - 2dℓ bytes, where ℓ is in bytes.
pub trait Rate: sealed::Rate {
    /// Rate type for this (SecurityLevel, Capacity) combination
    type Rate: ArraySize;
}

// Security level implementations
impl sealed::SecurityLevel for U16 {}
impl SecurityLevel for U16 {}

impl sealed::SecurityLevel for U24 {}
impl SecurityLevel for U24 {}

impl sealed::SecurityLevel for U32 {}
impl SecurityLevel for U32 {}

// Capacity implementations
impl sealed::Capacity for U1 {}
impl Capacity for U1 {}

impl sealed::Capacity for U2 {}
impl Capacity for U2 {}

// Rate implementations for all (SecurityLevel, Capacity) pairs
// r = 192 - 2 * d * ℓ

impl sealed::Rate for (U16, U1) {}
impl Rate for (U16, U1) {
    type Rate = U160;
}

impl sealed::Rate for (U16, U2) {}
impl Rate for (U16, U2) {
    type Rate = U128;
}

impl sealed::Rate for (U24, U1) {}
impl Rate for (U24, U1) {
    type Rate = U144;
}

impl sealed::Rate for (U24, U2) {}
impl Rate for (U24, U2) {
    type Rate = U96;
}

impl sealed::Rate for (U32, U1) {}
impl Rate for (U32, U1) {
    type Rate = U128;
}

impl sealed::Rate for (U32, U2) {}
impl Rate for (U32, U2) {
    type Rate = U64;
}

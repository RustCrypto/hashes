use digest::consts::U24;
use digest::typenum::{U1, U2, U16, U32, Unsigned};

mod sealed {
    /// Sealed trait to prevent external implementations of SecurityLevel.
    pub trait SecurityLevel {}

    /// Sealed trait to prevent external implementations of Capacity.
    pub trait Capacity {}
}

/// Security level trait for programmable algorithms.
///
/// Specified in Section 5.3 of STB 34.101.77-2020.
///
/// Standard levels: ℓ ∈ {128, 192, 256}.
///
/// Implemented for `U128`, `U192`, and `U256` from `digest::typenum`.
pub trait SecurityLevel: sealed::SecurityLevel + Unsigned {}

/// Capacity parameter for programmable algorithms.
///
/// Specified in Section 5.4 of STB 34.101.77-2020.
///
/// Capacity d ∈ {1, 2}.
///
/// Implemented for `U1` and `U2` from `digest::typenum`.
pub trait Capacity: sealed::Capacity + Unsigned {}

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

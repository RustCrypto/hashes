use digest::typenum::{U1, U2, U128, U192, U256, Unsigned};

/// Sealed trait to prevent external implementations.
pub trait Sealed {}

/// Security level trait for programmable algorithms.
///
/// Specified in Section 5.3 of STB 34.101.77-2020.
///
/// Standard levels: ℓ ∈ {128, 192, 256}.
pub trait SecurityLevel: Sealed {
    /// Type-level representation of ℓ
    type TypeLevel: Unsigned;
    /// Security level ℓ in bits
    const LEVEL: usize = <Self::TypeLevel as Unsigned>::USIZE;
}

/// Capacity parameter for programmable algorithms.
///
/// Specified in Section 5.4 of STB 34.101.77-2020.
///
/// Capacity d ∈ {1, 2}.
pub trait Capacity: Sealed {
    /// Type-level representation of d
    type TypeCapacity: Unsigned;
    /// Capacity d
    const CAPACITY: usize = <Self::TypeCapacity as Unsigned>::USIZE;
}

macro_rules! impl_type_with_sealed {
    (
        $(#[$meta:meta])*
        $name:ident: $trait:ident {
            $assoc_type:ident = $type_val:ty
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl Sealed for $name {}

        impl $trait for $name {
            type $assoc_type = $type_val;
        }
    };
}

impl_type_with_sealed! {
    /// Security level ℓ = 128
    Level128: SecurityLevel { TypeLevel = U128 }
}

impl_type_with_sealed! {
    /// Security level ℓ = 192
    Level192: SecurityLevel { TypeLevel = U192 }
}

impl_type_with_sealed! {
    /// Security level ℓ = 256
    Level256: SecurityLevel { TypeLevel = U256 }
}

impl_type_with_sealed! {
    /// Capacity d = 1
    Cap1: Capacity { TypeCapacity = U1 }
}

impl_type_with_sealed! {
    /// Capacity d = 2
    Cap2: Capacity { TypeCapacity = U2 }
}

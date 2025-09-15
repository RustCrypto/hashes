//! The BLAKE2s hash function: optimized for 32-bit CPUs.
//!
//! # Example
//!
//! ```
//! use blake2::blake2s::{blake2s, Params};
//!
//! let expected = "08d6cad88075de8f192db097573d0e829411cd91eb6ec65e8fc16c017edfdb74";
//! let hash = blake2s(b"foo");
//! assert_eq!(expected, &hash.to_hex());
//!
//! let hash = Params::new()
//!     .hash_length(16)
//!     .key(b"Squeamish Ossifrage")
//!     .personal(b"Shaftoe")
//!     .to_state()
//!     .update(b"foo")
//!     .update(b"bar")
//!     .update(b"baz")
//!     .finalize();
//!
//! assert_eq!("28325512782cbf5019424fa65da9a6c7", &hash.to_hex());
//! ```

pub(crate) mod backend;
pub(crate) mod state;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg_attr(docsrs, doc(cfg(any(target_arch = "x86", target_arch = "x86_64"))))]
pub mod many;

mod hash;
mod params;
#[cfg(test)]
mod test;

pub use self::{hash::Hash, params::Params, state::State};

use core::{fmt, mem::size_of};
use crypto_mac::{InvalidKeyLength, Mac, NewMac};
use digest::{
    consts::{U32, U64},
    generic_array::GenericArray,
    BlockInput, FixedOutputDirty, InvalidOutputSize, Reset, Update, VariableOutputDirty,
};

pub(crate) type Word = u32;
pub(crate) type Count = u64;
type Output = GenericArray<u8, U32>;

/// The max hash length.
pub const OUTBYTES: usize = 8 * size_of::<Word>();

/// The max key length.
pub const KEYBYTES: usize = 8 * size_of::<Word>();

/// The max salt length.
pub const SALTBYTES: usize = 2 * size_of::<Word>();

/// The max personalization length.
pub const PERSONALBYTES: usize = 2 * size_of::<Word>();

/// The number input bytes passed to each call to the compression function. Small benchmarks need
/// to use an even multiple of `BLOCKBYTES`, or else their apparent throughput will be low.
pub const BLOCKBYTES: usize = 16 * size_of::<Word>();

const IV: [Word; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Compute the BLAKE2s hash of a slice of bytes all at once, using default
/// parameters.
///
/// # Example
///
/// ```
/// # use blake2::blake2s::{blake2s, Params};
/// let expected = "08d6cad88075de8f192db097573d0e829411cd91eb6ec65e8fc16c017edfdb74";
/// let hash = blake2s(b"foo");
/// assert_eq!(expected, &hash.to_hex());
/// ```
pub fn blake2s(input: &[u8]) -> Hash {
    Params::new().hash(input)
}

/// Blake2s instance with a fixed output.
#[derive(Clone, Default)]
pub struct Blake2s {
    params: Params,
    state: State,
}

impl Blake2s {
    /// Creates a new hashing context with the full set of sequential-mode parameters.
    pub fn with_params(key: &[u8], salt: &[u8], persona: &[u8]) -> Self {
        Params::new()
            .key(key)
            .salt(salt)
            .personal(persona)
            .clone()
            .into()
    }
}

impl From<Params> for Blake2s {
    fn from(params: Params) -> Self {
        let state = params.to_state();
        Self { params, state }
    }
}

impl BlockInput for Blake2s {
    type BlockSize = U64;
}

impl Update for Blake2s {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.state.update(data.as_ref());
    }
}

impl FixedOutputDirty for Blake2s {
    type OutputSize = U32;

    fn finalize_into_dirty(&mut self, out: &mut Output) {
        let hash = self.state.finalize();
        out.copy_from_slice(hash.as_bytes());
    }
}

impl Reset for Blake2s {
    fn reset(&mut self) {
        self.state = self.params.to_state();
    }
}

impl NewMac for Blake2s {
    type KeySize = U32;

    fn new(key: &GenericArray<u8, U32>) -> Self {
        Params::new().key(key).clone().into()
    }

    fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        Ok(Params::new().key(key).clone().into())
    }
}

impl Mac for Blake2s {
    type OutputSize = U32;

    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    fn reset(&mut self) {
        <Self as Reset>::reset(self)
    }

    fn finalize(self) -> crypto_mac::Output<Self> {
        let mut output = GenericArray::<u8, Self::OutputSize>::default();
        output.copy_from_slice(self.state.finalize().as_bytes());
        crypto_mac::Output::new(output)
    }
}

opaque_debug::implement!(Blake2s);
digest::impl_write!(Blake2s);

/// Blake2s instance with a variable output.
#[derive(Clone, Default)]
pub struct VarBlake2s {
    params: Params,
    state: State,
}

impl VarBlake2s {
    /// Creates a new hashing context with a key.
    ///
    /// **WARNING!** If you plan to use it for variable output MAC, then
    /// make sure to compare codes in constant time! It can be done
    /// for example by using `subtle` crate.
    pub fn new_keyed(key: &[u8], output_size: usize) -> Self {
        Self::with_params(key, &[], &[], output_size)
    }

    /// Creates a new hashing context with the full set of sequential-mode parameters.
    pub fn with_params(key: &[u8], salt: &[u8], persona: &[u8], output_size: usize) -> Self {
        Params::new()
            .key(key)
            .salt(salt)
            .personal(persona)
            .hash_length(output_size)
            .clone()
            .into()
    }

    /// Updates the hashing context with more data.
    fn update(&mut self, data: &[u8]) {
        self.state.update(data.as_ref());
    }
}

impl From<Params> for VarBlake2s {
    fn from(params: Params) -> Self {
        let state = params.to_state();
        Self { params, state }
    }
}

impl BlockInput for VarBlake2s {
    type BlockSize = U64;
}

impl Update for VarBlake2s {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.update(data.as_ref());
    }
}

impl VariableOutputDirty for VarBlake2s {
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        Ok(Params::new().hash_length(output_size).clone().into())
    }

    fn output_size(&self) -> usize {
        self.params.hash_length as usize
    }

    fn finalize_variable_dirty(&mut self, f: impl FnOnce(&[u8])) {
        let hash = self.state.finalize();
        f(hash.as_bytes())
    }
}

impl Reset for VarBlake2s {
    fn reset(&mut self) {
        self.state = self.params.to_state();
    }
}

opaque_debug::implement!(VarBlake2s);
digest::impl_write!(VarBlake2s);

// Paint a byte pattern that won't repeat, so that we don't accidentally miss
// buffer offset bugs. This is the same as what Bao uses in its tests.
#[cfg(test)]
pub(crate) fn paint_test_input(buf: &mut [u8]) {
    let mut offset = 0;
    let mut counter: u32 = 1;
    while offset < buf.len() {
        let bytes = counter.to_le_bytes();
        let take = core::cmp::min(bytes.len(), buf.len() - offset);
        buf[offset..][..take].copy_from_slice(&bytes[..take]);
        counter += 1;
        offset += take;
    }
}

// This module is pub for internal benchmarks only. Please don't use it.
#[doc(hidden)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod benchmarks {
    use super::*;
    use crate::blake2sp;

    pub fn force_portable(params: &mut Params) {
        params.implementation = backend::Implementation::portable();
    }

    pub fn force_portable_blake2sp(params: &mut blake2sp::Params) {
        blake2sp::force_portable(params);
    }
}

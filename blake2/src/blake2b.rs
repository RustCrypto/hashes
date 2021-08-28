//! The BLAKE2b hash function: optimized for 64-bit CPUs.
//!
//! # Example
//!
//! ```
//! use blake2::blake2b::{blake2b, Params};
//!
//! let expected = "ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6d\
//!                 c1e723fb3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d";
//! let hash = blake2b(b"foo");
//! assert_eq!(expected, &hash.to_hex());
//!
//! let hash = Params::new()
//!     .hash_length(16)
//!     .key(b"The Magic Words are Squeamish Ossifrage")
//!     .personal(b"L. P. Waterhouse")
//!     .to_state()
//!     .update(b"foo")
//!     .update(b"bar")
//!     .update(b"baz")
//!     .finalize();
//!
//! assert_eq!("ee8ff4e9be887297cf79348dc35dab56", &hash.to_hex());
//! ```

pub(crate) mod backend;
pub mod many;

mod params;

#[cfg(test)]
mod test;

pub use self::params::Params;

use arrayref::mut_array_refs;
use core::{cmp, fmt, mem::size_of};

pub(crate) type Word = u64;
pub(crate) type Count = u128;

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
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

const SIGMA: [[u8; 16]; 12] = [
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
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Compute the BLAKE2b hash of a slice of bytes all at once, using default
/// parameters.
///
/// # Example
///
/// ```
/// # use blake2::blake2b::{blake2b, Params};
/// let expected = "ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6d\
///                 c1e723fb3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d";
/// let hash = blake2b(b"foo");
/// assert_eq!(expected, &hash.to_hex());
/// ```
pub fn blake2b(input: &[u8]) -> Hash {
    Params::new().hash(input)
}

/// An incremental hasher for BLAKE2b.
///
/// To construct a `State` with non-default parameters, see `Params::to_state`.
///
/// # Example
///
/// ```
/// use blake2::blake2b::{blake2b, State};
///
/// let mut state = State::new();
///
/// state.update(b"foo");
/// assert_eq!(blake2b(b"foo"), state.finalize());
///
/// state.update(b"bar");
/// assert_eq!(blake2b(b"foobar"), state.finalize());
/// ```
#[derive(Clone)]
pub struct State {
    words: [Word; 8],
    count: Count,
    buf: [u8; BLOCKBYTES],
    buflen: u8,
    last_node: backend::LastNode,
    hash_length: u8,
    implementation: backend::Implementation,
    is_keyed: bool,
}

impl State {
    /// Equivalent to `State::default()` or `Params::default().to_state()`.
    pub fn new() -> Self {
        Self::with_params(&Params::default())
    }

    fn with_params(params: &Params) -> Self {
        let mut state = Self {
            words: params.to_words(),
            count: 0,
            buf: [0; BLOCKBYTES],
            buflen: 0,
            last_node: params.last_node,
            hash_length: params.hash_length,
            implementation: params.implementation,
            is_keyed: params.key_length > 0,
        };
        if state.is_keyed {
            state.buf = params.key_block;
            state.buflen = state.buf.len() as u8;
        }
        state
    }

    fn fill_buf(&mut self, input: &mut &[u8]) {
        let take = cmp::min(BLOCKBYTES - self.buflen as usize, input.len());
        self.buf[self.buflen as usize..self.buflen as usize + take].copy_from_slice(&input[..take]);
        self.buflen += take as u8;
        *input = &input[take..];
    }

    // If the state already has some input in its buffer, try to fill the buffer and perform a
    // compression. However, only do the compression if there's more input coming, otherwise it
    // will give the wrong hash it the caller finalizes immediately after.
    fn compress_buffer_if_possible(&mut self, input: &mut &[u8]) {
        if self.buflen > 0 {
            self.fill_buf(input);
            if !input.is_empty() {
                self.implementation.compress1_loop(
                    &self.buf,
                    &mut self.words,
                    self.count,
                    self.last_node,
                    backend::Finalize::No,
                    backend::Stride::Serial,
                );
                self.count = self.count.wrapping_add(BLOCKBYTES as Count);
                self.buflen = 0;
            }
        }
    }

    /// Add input to the hash. You can call `update` any number of times.
    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        // If we have a partial buffer, try to complete it.
        self.compress_buffer_if_possible(&mut input);
        // While there's more than a block of input left (which also means we cleared the buffer
        // above), compress blocks directly without copying.
        let mut end = input.len().saturating_sub(1);
        end -= end % BLOCKBYTES;
        if end > 0 {
            self.implementation.compress1_loop(
                &input[..end],
                &mut self.words,
                self.count,
                self.last_node,
                backend::Finalize::No,
                backend::Stride::Serial,
            );
            self.count = self.count.wrapping_add(end as Count);
            input = &input[end..];
        }
        // Buffer any remaining input, to be either compressed or finalized in a subsequent call.
        // Note that this represents some copying overhead, which in theory we could avoid in
        // all-at-once setting. A function hardcoded for exactly BLOCKSIZE input bytes is about 10%
        // faster than using this implementation for the same input.
        self.fill_buf(&mut input);
        self
    }

    /// Finalize the state and return a `Hash`. This method is idempotent, and calling it multiple
    /// times will give the same result. It's also possible to `update` with more input in between.
    pub fn finalize(&self) -> Hash {
        let mut words_copy = self.words;
        self.implementation.compress1_loop(
            &self.buf[..self.buflen as usize],
            &mut words_copy,
            self.count,
            self.last_node,
            backend::Finalize::Yes,
            backend::Stride::Serial,
        );
        Hash {
            bytes: state_words_to_bytes(&words_copy),
            len: self.hash_length,
        }
    }

    /// Set a flag indicating that this is the last node of its level in a tree hash. This is
    /// equivalent to [`Params::last_node`], except that it can be set at any time before calling
    /// `finalize`. That allows callers to begin hashing a node without knowing ahead of time
    /// whether it's the last in its level. For more details about the intended use of this flag
    /// [the BLAKE2 spec].
    ///
    /// [`Params::last_node`]: struct.Params.html#method.last_node
    /// [the BLAKE2 spec]: https://blake2.net/blake2.pdf
    pub fn set_last_node(&mut self, last_node: bool) -> &mut Self {
        self.last_node = if last_node {
            backend::LastNode::Yes
        } else {
            backend::LastNode::No
        };
        self
    }

    /// Return the total number of bytes input so far.
    ///
    /// Note that `count` doesn't include the bytes of the key block, if any.
    /// It's exactly the total number of input bytes fed to `update`.
    pub fn count(&self) -> Count {
        let mut ret = self.count.wrapping_add(self.buflen as Count);
        if self.is_keyed {
            ret -= BLOCKBYTES as Count;
        }
        ret
    }
}

#[inline(always)]
pub(crate) fn state_words_to_bytes(state_words: &[Word; 8]) -> [u8; OUTBYTES] {
    let mut bytes = [0; OUTBYTES];
    {
        const W: usize = size_of::<Word>();
        let refs = mut_array_refs!(&mut bytes, W, W, W, W, W, W, W, W);
        *refs.0 = state_words[0].to_le_bytes();
        *refs.1 = state_words[1].to_le_bytes();
        *refs.2 = state_words[2].to_le_bytes();
        *refs.3 = state_words[3].to_le_bytes();
        *refs.4 = state_words[4].to_le_bytes();
        *refs.5 = state_words[5].to_le_bytes();
        *refs.6 = state_words[6].to_le_bytes();
        *refs.7 = state_words[7].to_le_bytes();
    }
    bytes
}

#[cfg(feature = "std")]
impl std::io::Write for State {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NB: Don't print the words. Leaking them would allow length extension.
        write!(
            f,
            "State {{ count: {}, hash_length: {}, last_node: {} }}",
            self.count(),
            self.hash_length,
            self.last_node.yes(),
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::with_params(&Params::default())
    }
}

type HexString = arrayvec::ArrayString<[u8; 2 * OUTBYTES]>;

/// A finalized BLAKE2 hash, with constant-time equality.
#[derive(Clone, Copy)]
pub struct Hash {
    pub(crate) bytes: [u8; OUTBYTES],
    pub(crate) len: u8,
}

impl Hash {
    /// Convert the hash to a byte slice. Note that if you're using BLAKE2 as a MAC, you need
    /// constant time equality, which `&[u8]` doesn't provide.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Convert the hash to a byte array. Note that if you're using BLAKE2 as a
    /// MAC, you need constant time equality, which arrays don't provide. This
    /// panics in debug mode if the length of the hash isn't `OUTBYTES`.
    #[inline]
    pub fn as_array(&self) -> &[u8; OUTBYTES] {
        debug_assert_eq!(self.len as usize, OUTBYTES);
        &self.bytes
    }

    /// Convert the hash to a lowercase hexadecimal
    /// [`ArrayString`](https://docs.rs/arrayvec/0.4/arrayvec/struct.ArrayString.html).
    pub fn to_hex(self) -> HexString {
        bytes_to_hex(self.as_bytes())
    }
}

fn bytes_to_hex(bytes: &[u8]) -> HexString {
    let mut s = arrayvec::ArrayString::new();
    let table = b"0123456789abcdef";
    for &b in bytes {
        s.push(table[(b >> 4) as usize] as char);
        s.push(table[(b & 0xf) as usize] as char);
    }
    s
}

/// This implementation is constant time, if the two hashes are the same length.
impl PartialEq for Hash {
    fn eq(&self, other: &Hash) -> bool {
        constant_time_eq::constant_time_eq(self.as_bytes(), other.as_bytes())
    }
}

/// This implementation is constant time, if the slice is the same length as the hash.
impl PartialEq<[u8]> for Hash {
    fn eq(&self, other: &[u8]) -> bool {
        constant_time_eq::constant_time_eq(self.as_bytes(), other)
    }
}

impl Eq for Hash {}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(0x{})", self.to_hex())
    }
}

// Paint a byte pattern that won't repeat, so that we don't accidentally miss
// buffer offset bugs. This is the same as what Bao uses in its tests.
#[cfg(test)]
pub(crate) fn paint_test_input(buf: &mut [u8]) {
    let mut offset = 0;
    let mut counter: u32 = 1;
    while offset < buf.len() {
        let bytes = counter.to_le_bytes();
        let take = cmp::min(bytes.len(), buf.len() - offset);
        buf[offset..][..take].copy_from_slice(&bytes[..take]);
        counter += 1;
        offset += take;
    }
}

// This module is pub for internal benchmarks only. Please don't use it.
#[doc(hidden)]
pub mod benchmarks {
    use crate::blake2bp;

    use super::*;

    pub fn force_portable(params: &mut Params) {
        params.implementation = backend::Implementation::portable();
    }

    pub fn force_portable_blake2bp(params: &mut blake2bp::Params) {
        blake2bp::force_portable(params);
    }
}

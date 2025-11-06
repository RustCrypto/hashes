//! Blake2X extensible output function (XOF) implementations
//!
//! Blake2X is an extensible output function (XOF) based on Blake2b and Blake2s that can produce
//! hash outputs of arbitrary length by using a tree hashing mode. This module provides both
//! Blake2Xb (based on Blake2b) and Blake2Xs (based on Blake2s) implementations.
//!
//! # Algorithm
//!
//! Blake2X works by first computing a root hash using the underlying Blake2 algorithm
//! (Blake2b for Blake2Xb, Blake2s for Blake2Xs) with the desired output length incorporated
//! into the parameter block. Then, it uses tree hashing to generate expansion nodes that
//! produce the actual extended output.
//!
//! The algorithm follows this process:
//! 1. Compute root hash H₀ = Blake2(M, XOF_length) where M is the input message
//! 2. For each output block i, compute Hᵢ = Blake2(H₀, node_parameters)
//! 3. Concatenate blocks to produce the desired output length
//!
//! # Usage
//!
//! ```
//! # #[cfg(feature = "blake2x")] {
//! use blake2::Blake2xb;
//! use digest::{Update, ExtendableOutput, XofReader};
//!
//! // Create a Blake2Xb hasher for 100 bytes of output
//! let mut hasher = Blake2xb::new(100);
//! hasher.update(b"hello world");
//! let mut reader = hasher.finalize_xof();
//!
//! // Read the output
//! let mut output = vec![0u8; 100];
//! reader.read(&mut output);
//! # }
//! ```
//!
//! # Keyed Hashing
//!
//! Both Blake2Xb and Blake2Xs support keyed hashing for message authentication:
//!
//! ```
//! # #[cfg(feature = "blake2x")] {
//! use blake2::Blake2xs;
//! use digest::{Update, ExtendableOutput, XofReader};
//!
//! let key = b"my secret key";
//! let mut hasher = Blake2xs::new_with_key(key, 64);
//! hasher.update(b"authenticated message");
//! let mut reader = hasher.finalize_xof();
//!
//! let mut output = vec![0u8; 64];
//! reader.read(&mut output);
//! # }
//! ```
//!
//! # Features
//!
//! - **Arbitrary output length**: Generate outputs from 1 byte up to 2³²-1 bytes (Blake2Xb) or 2¹⁶-1 bytes (Blake2Xs)
//! - **Incremental output**: Read output incrementally without buffering the entire result
//! - **Keyed hashing**: Support for message authentication using secret keys
//! - **Streaming**: Process input data in chunks using the standard `Update` trait
//! - **No-std compatible**: Works in embedded and no-std environments
//!
//! # Security
//!
//! Blake2X inherits the security properties of the underlying Blake2 algorithm while providing
//! extended output capability. The XOF construction ensures that outputs of different lengths
//! are cryptographically independent.

use core::fmt;
use digest::{
    HashMarker,
    block_api::{
        Block, Buffer, BufferKindUser, ExtendableOutputCore, UpdateCore, VariableOutputCore,
        XofReaderCore,
    },
    block_buffer::{Lazy, LazyBuffer},
    consts::{U32, U64, U128},
    crypto_common::{AlgorithmName, BlockSizeUser, Output, hazmat::SerializableState},
};

#[cfg(feature = "reset")]
use digest::crypto_common::Reset;

use crate::consts::{BLAKE2B_IV, BLAKE2S_IV};
use crate::simd::{u32x4, u64x4};

// Generate Blake2xb implementation
blake2x_impl!(
    Blake2xbCore,
    Blake2xbReaderCore,
    Blake2xb,
    Blake2xbReader,
    "Blake2xb",
    u64,
    u64x4,
    U64,
    64,
    U128,
    U64,
    u32,
    BLAKE2B_IV,
    "Blake2Xb extensible output function hasher.\n\nBlake2Xb is based on Blake2b and can produce outputs up to 2³²-1 bytes.",
    crate::Blake2bVarCore,
);

// Generate Blake2xs implementation
blake2x_impl!(
    Blake2xsCore,
    Blake2xsReaderCore,
    Blake2xs,
    Blake2xsReader,
    "Blake2xs",
    u32,
    u32x4,
    U32,
    32,
    U64,
    U32,
    u16,
    BLAKE2S_IV,
    "Blake2Xs extensible output function hasher.\n\nBlake2Xs is based on Blake2s and can produce outputs up to 2¹⁶-1 bytes.",
    crate::Blake2sVarCore,
);

impl Blake2xb {
    /// Creates a new Blake2Xb hasher for a specified output length.
    ///
    /// # Arguments
    ///
    /// * `output_size` - The desired output length in bytes (1 to 2³²-1)
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "blake2x")] {
    /// use blake2::Blake2xb;
    /// use digest::{Update, ExtendableOutput, XofReader};
    ///
    /// let mut hasher = Blake2xb::new(64);
    /// hasher.update(b"hello");
    /// hasher.update(b" world");
    ///
    /// let mut reader = hasher.finalize_xof();
    /// let mut output = vec![0u8; 64];
    /// reader.read(&mut output);
    /// # }
    /// ```
    pub fn new(output_size: u32) -> Self {
        Self {
            core: Blake2xbCore::new(output_size),
            buffer: Default::default(),
        }
    }

    /// Creates a new keyed Blake2Xb hasher for a specified output length.
    ///
    /// Keyed hashing allows for message authentication by incorporating a secret key
    /// into the hash computation. This provides both integrity and authenticity.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key (up to 64 bytes for Blake2Xb)
    /// * `output_size` - The desired output length in bytes (1 to 2³²-1)
    ///
    /// # Security
    ///
    /// The key should be kept secret and should have sufficient entropy. Keys shorter
    /// than 32 bytes may have reduced security properties.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "blake2x")] {
    /// use blake2::Blake2xb;
    /// use digest::{Update, ExtendableOutput, XofReader};
    ///
    /// let key = b"my_secret_authentication_key_32b";
    /// let mut hasher = Blake2xb::new_with_key(key, 32);
    /// hasher.update(b"authenticated message");
    ///
    /// let mut reader = hasher.finalize_xof();
    /// let mut mac = vec![0u8; 32];
    /// reader.read(&mut mac);
    ///
    /// // The mac can now be used to verify message authenticity
    /// # }
    /// ```
    pub fn new_with_key(key: &[u8], output_size: u32) -> Self {
        // Prepend the key as the first data block according to Blake2 specification
        let mut key_block = Block::<Blake2xbCore>::default();
        key_block[..key.len()].copy_from_slice(key);

        Self {
            core: Blake2xbCore::new_with_key(key, output_size),
            buffer: LazyBuffer::new(&key_block),
        }
    }
}

impl Blake2xs {
    /// Creates a new Blake2Xs hasher for a specified output length.
    ///
    /// # Arguments
    ///
    /// * `output_size` - The desired output length in bytes (1 to 65535)
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "blake2x")] {
    /// use blake2::Blake2xs;
    /// use digest::{Update, ExtendableOutput, XofReader};
    ///
    /// let mut hasher = Blake2xs::new(32);
    /// hasher.update(b"hello");
    /// hasher.update(b" world");
    ///
    /// let mut reader = hasher.finalize_xof();
    /// let mut output = vec![0u8; 32];
    /// reader.read(&mut output);
    /// # }
    /// ```
    pub fn new(output_size: u16) -> Self {
        Self {
            core: Blake2xsCore::new(output_size),
            buffer: Default::default(),
        }
    }

    /// Creates a new keyed Blake2Xs hasher for a specified output length.
    ///
    /// Keyed hashing allows for message authentication by incorporating a secret key
    /// into the hash computation. This provides both integrity and authenticity.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key (up to 32 bytes for Blake2Xs)
    /// * `output_size` - The desired output length in bytes (1 to 65535)
    ///
    /// # Security
    ///
    /// The key should be kept secret and should have sufficient entropy. Keys shorter
    /// than 16 bytes may have reduced security properties.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "blake2x")] {
    /// use blake2::Blake2xs;
    /// use digest::{Update, ExtendableOutput, XofReader};
    ///
    /// let key = b"my_secret_key_16";
    /// let mut hasher = Blake2xs::new_with_key(key, 48);
    /// hasher.update(b"authenticated message");
    ///
    /// let mut reader = hasher.finalize_xof();
    /// let mut mac = vec![0u8; 48];
    /// reader.read(&mut mac);
    ///
    /// // The mac can now be used to verify message authenticity
    /// # }
    /// ```
    pub fn new_with_key(key: &[u8], output_size: u16) -> Self {
        // Prepend the key as the first data block according to Blake2 specification
        let mut key_block = Block::<Blake2xsCore>::default();
        key_block[..key.len()].copy_from_slice(key);

        Self {
            core: Blake2xsCore::new_with_key(key, output_size),
            buffer: LazyBuffer::new(&key_block),
        }
    }
}

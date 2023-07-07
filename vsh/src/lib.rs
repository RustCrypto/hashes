//! An implementation of the [Vsh][1] cryptographic hash algorithms.
//!
//! This is basic VSH implementation.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use vsh::{Vsh, Digest};
//!
//! // Create a Vsh object
//! let mut hasher = Vsh::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // Acquire hash digest which in this case is BigUint.
//! let result = hasher.finalize();
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Very_smooth_hash
//! [2]: https://github.com/RustCrypto/hashes

use digest::{
    core_api::{
        AlgorithmName
    },
    HashMarker,
};
use core::fmt;
use std::vec::Vec;
use num::bigint::BigUint;
mod vsh;

/// Core Vsh hasher state.
#[derive(Clone)]
pub struct VshCore {
    bytes: Vec<u8>
}

impl HashMarker for VshCore {}



impl AlgorithmName for VshCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Vsh")
    }
}

impl fmt::Debug for VshCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VshCore { ... }")
    }
}



impl VshCore {
    pub fn new() -> Self {
        let bytes: Vec<u8> = Vec::new();
        VshCore { bytes: bytes }
    }

    pub fn update(&mut self, data: &Vec<u8>) {
        self.bytes = data.to_vec();
    }

    pub fn finalize(&mut self) -> Result<BigUint, String> {
        let vhs_x:Vec<usize>;
        match vsh::validate_and_pad_input(self.bytes.clone()) {
            Ok(result) => {
                vhs_x = vsh::calculate_vhs_of_x(result);
            },
            Err(error) => {
                return Err(error);
            }
        }
        let primes = vsh::get_prime_list(vhs_x);
        
        let hash_of_data: BigUint = vsh::do_mod_with_products(primes);
        Ok(hash_of_data)
    }
}
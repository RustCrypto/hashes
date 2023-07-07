//! An implementation of the [Vsh][1] cryptographic hash algorithms.
//!
//! Vsh is a variant of the original Vsh with a small padding tweak.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use vsh::{Vsh, Digest};
//!
//! // create a Vsh object
//! let mut hasher = Vsh::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 24]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("4c8fbddae0b6f25832af45e7c62811bb64ec3e43691e9cc3"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Vsh_(hash_function)
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
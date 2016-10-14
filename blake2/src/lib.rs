#![no_std]
extern crate byte_tools;
extern crate digest;
// extern crate crypto_mac;
extern crate crypto_ops;
extern crate generic_array;

mod consts;

mod blake2b;
pub use blake2b::{Blake2b, Blake2b512};

mod blake2s;
pub use blake2s::{Blake2s, Blake2s256};

pub use digest::Digest;

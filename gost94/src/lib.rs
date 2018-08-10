#![no_std]
extern crate byte_tools;
extern crate block_buffer;
#[macro_use] pub extern crate digest;
#[macro_use] extern crate opaque_debug;
#[cfg(feature = "std")]
extern crate std;

#[macro_use]
mod macros;

mod gost94;
mod s2015;
mod cryptopro;
mod test_param;

pub use digest::Digest;

pub use gost94::Gost94;
pub use s2015::Gost94s2015;
pub use cryptopro::Gost94CryptoPro;
pub use test_param::Gost94Test;

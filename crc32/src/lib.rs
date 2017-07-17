// //! The [CRC32][1] hash function (ISO/IEC/IEEE 8802-3 standard).
// //!
// //! [1]: https://en.wikipedia.org/wiki/Cyclic_redundancy_check


#![no_std]
extern crate byte_tools;
#[cfg(feature = "generic")]
extern crate generic_array;
#[cfg(feature = "generic")]
extern crate digest;

use byte_tools::write_u32_be;
#[cfg(feature = "generic")]
pub use digest::Digest;
#[cfg(feature = "generic")]
use generic_array::GenericArray;
#[cfg(feature = "generic")]
use generic_array::typenum::{U4, U64};

mod consts;


#[derive(Copy, Clone)]
pub struct CRC32 {
    state: u32,
}


impl Default for CRC32 {
    fn default() -> Self {
        CRC32 {
            state: 0,
        }
    }
}


impl CRC32 {
    #[inline]
    fn finalize(self) -> u32 {
        self.state
    }

    #[inline]
    pub fn hash(self) -> u32 {
        self.state
    }

    #[inline]
    pub fn consume(&mut self, input: &[u8]) {

        let mut crc = !self.state;
        let mut pos: u32;

        for &byte in input.iter() {
            pos = (crc ^ byte as u32) & 0xFF;
            crc = (crc >> 8) ^ consts::TABLE_CRC32[pos as usize];
        }

        self.state = !crc;
    }
}


#[cfg(feature = "generic")]
impl digest::BlockInput for CRC32 {
    type BlockSize = U64;
}

#[cfg(feature = "generic")]
impl digest::Input for CRC32 {
    #[inline]
    fn process(&mut self, input: &[u8]) {
        self.consume(input);
    }
}

#[cfg(feature = "generic")]
impl digest::FixedOutput for CRC32 {
    type OutputSize = U4;

    #[inline]
    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = GenericArray::default();
        write_u32_be(&mut out, self.finalize());
        out
    }
}

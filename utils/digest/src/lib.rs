#![no_std]
extern crate generic_array;
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

/// The Digest trait specifies an interface common to digest functions
pub trait Digest {
    type OutputSize: ArrayLength<u8>;
    type BlockSize: ArrayLength<u8>;

    /// Digest input data. This method can be called repeatedly
    /// for use with streaming messages.
    fn input(&mut self, input: &[u8]);

    /// Retrieve the digest result. This method consumes digest instance.
    fn result(self) -> GenericArray<u8, Self::OutputSize>;

    /// Get the block size in bytes.
    fn block_bytes(&self) -> usize { Self::BlockSize::to_usize() }

    /// Get the block size in bits.
    fn block_bits(&self) -> usize { 8 * Self::BlockSize::to_usize() }

    /// Get the output size in bytes.
    fn output_bytes(&self) -> usize { Self::OutputSize::to_usize() }

    /// Get the output size in bits.
    fn output_bits(&self) -> usize { 8 * Self::OutputSize::to_usize() }
}

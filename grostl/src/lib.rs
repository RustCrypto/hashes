// #![no_std]
extern crate digest;
extern crate generic_array;

use std::marker::PhantomData;

use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{
    Cmp, Compare, Greater, Less, Same,
    U256, U257, U512, U1024,
};

pub type GrostlSmall<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U512>,
          Compare<OutputSize, U257>: Same<Less>
    = Grostl<OutputSize, U512>;

pub type GrostlBig<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U512>,
          Compare<OutputSize, U256>: Same<Greater>
    = Grostl<OutputSize, U1024>;

pub struct Grostl<OutputSize, BlockSize> {
    phantom1: PhantomData<OutputSize>,
    phantom2: PhantomData<BlockSize>,
}

impl<OutputSize, BlockSize> Grostl<OutputSize, BlockSize> {
    fn new() -> Grostl<OutputSize, BlockSize> {
        Grostl { phantom1: PhantomData, phantom2: PhantomData }
    }
}

impl<OutputSize, BlockSize> Default for Grostl<OutputSize, BlockSize> {
    fn default() -> Self { Self::new() }
}

impl<OutputSize: ArrayLength<u8>, BlockSize: ArrayLength<u8>> Digest for Grostl<OutputSize, BlockSize> {
    type OutputSize = OutputSize;
    type BlockSize = BlockSize;

    fn input(&mut self, input: &[u8]) {
    }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        GenericArray::default()
    }
}

// #![no_std]
extern crate byte_tools;
extern crate digest;
extern crate generic_array;

use std::marker::PhantomData;

use byte_tools::write_u64_le;
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

pub struct Grostl<OutputSize, BlockSize: ArrayLength<u8>> {
    state: GenericArray<u8, BlockSize>,
    phantom: PhantomData<OutputSize>,
}

fn xor_generic_array<L: ArrayLength<u8>>(
    a1: &GenericArray<u8, L>,
    a2: &GenericArray<u8, L>,
) -> GenericArray<u8, L> {
    let mut res = GenericArray::default();
    for i in 0..L::to_usize() {
        res[i] = a1[i] ^ a2[i];
    }
    res
}

impl<OutputSize: ArrayLength<u8>, BlockSize: ArrayLength<u8>> Grostl<OutputSize, BlockSize> {
    fn new() -> Grostl<OutputSize, BlockSize> {
        let block_bytes = BlockSize::to_usize() / 8;
        let mut iv = Vec::with_capacity(block_bytes);
        write_u64_le(&mut iv, BlockSize::to_usize() as u64);
        Grostl {
            state: GenericArray::clone_from_slice(&iv),
            phantom: PhantomData,
        }
    }

    fn get_padding_chunk(input: &[u8]) -> Vec<u8> {
        let l = input.len();
        let bs = BlockSize::to_usize();

        let num_padding_bits = -1 * ((8 * l + 64) % bs) as isize;
        let num_padding_bytes = num_padding_bits as usize / 8;
        debug_assert!(num_padding_bytes < 512);

        let mut padding_chunk = Vec::with_capacity(bs / 8);
        padding_chunk.extend(input[l - (l % bs)..].iter());
        padding_chunk.push(128);
        for _ in 0..num_padding_bytes - 1 {
            padding_chunk.push(0)
        }
        let num_blocks = (l + num_padding_bytes) / bs;
        write_u64_le(&mut padding_chunk[bs - 8..], num_blocks as u64);

        padding_chunk
    }

    fn compress(
        &self,
        input_block: &GenericArray<u8, BlockSize>,
    ) -> GenericArray<u8, BlockSize> {
        xor_generic_array(
            &xor_generic_array(
                &self.p(&xor_generic_array(&self.state, input_block)),
                &self.q(input_block)
            ),
            &self.state,
        )
    }

    fn p(
        &self,
        input_block: &GenericArray<u8, BlockSize>,
    ) -> GenericArray<u8, BlockSize> {
        GenericArray::default()
    }

    fn q(
        &self,
        input_block: &GenericArray<u8, BlockSize>,
    ) -> GenericArray<u8, BlockSize> {
        GenericArray::default()
    }

    fn finalize(self) -> GenericArray<u8, OutputSize> {
        GenericArray::default()
    }
}

impl<OutputSize: ArrayLength<u8>, BlockSize: ArrayLength<u8>> Default for Grostl<OutputSize, BlockSize> {
    fn default() -> Self { Self::new() }
}

impl<OutputSize: ArrayLength<u8>, BlockSize: ArrayLength<u8>> Digest for Grostl<OutputSize, BlockSize> {
    type OutputSize = OutputSize;
    type BlockSize = BlockSize;

    fn input(&mut self, input: &[u8]) {
        for chunk in input.chunks(self.block_bytes()) {
            if chunk.len() < self.block_bytes() {
                let padding_chunk =
                    Grostl::<OutputSize, BlockSize>::get_padding_chunk(input);
                self.state = self.compress(
                    GenericArray::from_slice(&padding_chunk),
                );
            } else {
                self.state = self.compress(GenericArray::from_slice(chunk));
            }
        }
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize()
    }
}

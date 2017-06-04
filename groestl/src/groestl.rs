use core::ops::Div;

use digest;
use byte_tools::write_u64_be;
use digest_buffer::DigestBuffer;
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{Quot, U8};

use state::{GroestlState, xor_generic_array};

#[derive(Copy, Clone)]
pub struct Groestl<BlockSize>
    where BlockSize: ArrayLength<u8> + Div<U8>,
          BlockSize::ArrayType: Copy,
          Quot<BlockSize, U8>: ArrayLength<u8>,
{
    buffer: DigestBuffer<BlockSize>,
    state: GroestlState<BlockSize>,
    pub output_size: usize,
}

impl<BlockSize> Groestl<BlockSize>
    where BlockSize: ArrayLength<u8> + Div<U8>,
          BlockSize::ArrayType: Copy,
          Quot<BlockSize, U8>: ArrayLength<u8>,
{
    pub fn new(output_size: usize) -> Result<Self, digest::InvalidLength> {
        match BlockSize::to_usize() {
            128 => {
                if output_size <= 32 || output_size > 64 {
                    return Err(digest::InvalidLength);
                }
            },
            64 => {
                if output_size == 0 || output_size > 32 {
                    return Err(digest::InvalidLength);
                }
            },
            _ => unreachable!(),
        };

        Ok(Groestl{
            buffer: Default::default(),
            state: GroestlState::new(output_size),
            output_size: output_size
        })
    }

    pub fn process(&mut self, input: &[u8]) {
        let state = &mut self.state;
        self.buffer.input(
            input,
            |b: &GenericArray<u8, BlockSize>| { state.compress(b); },
        );
    }

    pub fn finalize(mut self) -> GenericArray<u8, BlockSize> {
        {
            let state = &mut self.state;
            self.buffer.standard_padding(
                8,
                |b: &GenericArray<u8, BlockSize>| { state.compress(b); },
            );
        }
        {
            let mut buf = self.buffer.next(8);
            write_u64_be(&mut buf, (self.state.num_blocks + 1) as u64);
        }
        let state = &mut self.state;
        state.compress(self.buffer.full_buffer());
        xor_generic_array(&state.p(&state.state), &state.state)
    }
}

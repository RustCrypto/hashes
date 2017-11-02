use core::ops::Div;

use digest;
use block_buffer::BlockBuffer;
use digest::generic_array::{ArrayLength, GenericArray};
use digest::generic_array::typenum::{Quot, U8};

use state::{GroestlState, xor_generic_array};

#[derive(Clone)]
pub struct Groestl<BlockSize>
    where BlockSize: ArrayLength<u8> + Div<U8> + Default,
          BlockSize::ArrayType: Copy,
          Quot<BlockSize, U8>: ArrayLength<u8>,
{
    buffer: BlockBuffer<BlockSize>,
    state: GroestlState<BlockSize>,
    pub output_size: usize,
}

impl<BlockSize> Groestl<BlockSize>
    where BlockSize: ArrayLength<u8> + Div<U8> + Default,
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
        let state = &mut self.state;
        let mut l = if self.buffer.remaining() <= 8 {
            state.num_blocks + 2
        } else {
            state.num_blocks + 1
        };
        // remove this mess by adding `len_padding_be` method
        let l = if cfg!(target_endian = "little") { l.to_be() } else { l.to_le() };
        self.buffer.len_padding(l, |b| {
            println!("{:?}", b);
            state.compress(b)
        });
        xor_generic_array(&state.p(&state.state), &state.state)
    }
}

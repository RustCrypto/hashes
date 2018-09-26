#![cfg_attr(feature = "cargo-clippy", allow(needless_range_loop, inline_always))]
use digest::{Input, BlockInput, FixedOutput, Reset};
use digest::generic_array::typenum::{Unsigned, U64};
use digest::generic_array::{GenericArray, ArrayLength};
use block_buffer::BlockBuffer;
use block_buffer::block_padding::ZeroPadding;
use block_buffer::byteorder::{LE, ByteOrder};
use byte_tools::copy;
use core::marker::PhantomData;

use consts::{BLOCK_SIZE, C};
use table::SHUFFLED_LIN_TABLE;

type Block = [u8; 64];

#[derive(Copy, Clone)]
struct StreebogState {
    h: Block,
    n: Block,
    sigma: Block,
}

#[inline(always)]
fn lps(h: &mut Block, n: &Block) {
    for i in 0..64 {
        h[i] ^= n[i];
    }

    let mut buf = [0u64; 8];

    for i in 0..4 {
        for j in 0..8 {
            let b = h[2*i + 8*j] as usize;
            buf[2*i] ^= SHUFFLED_LIN_TABLE[j][b];
            let b = h[2*i+1 + 8*j] as usize;
            buf[2*i+1] ^= SHUFFLED_LIN_TABLE[j][b];
        }
    }

    LE::write_u64_into(&buf, h);
}

impl StreebogState {
    fn g(&mut self, n: &Block, m: &Block) {
        let mut key = [0u8; 64];
        let mut block = [0u8; 64];

        copy(&self.h, &mut key);
        copy(m, &mut block);

        lps(&mut key, n);

        for i in 0..12 {
            lps(&mut block, &key);
            lps(&mut key, &C[i]);
        }

        for i in 0..64 {
            self.h[i] ^= block[i] ^ key[i]  ^ m[i];
        }
    }

    fn update_sigma(&mut self, m: &Block) {
        let mut over = false;
        for (a, b) in self.sigma.iter_mut().zip(m.iter()) {
            let (res, loc_over) = (*a).overflowing_add(*b);
            *a = res;
            if over { *a += 1; }
            over = loc_over;
        }
    }

    fn update_n(&mut self, mut l: u8) {
        let res = u16::from(self.n[0]) + (u16::from(l) << 3);
        self.n[0] = (res & 0xff) as u8;
        l = (res >> 8) as u8;

        for a in self.n.iter_mut().skip(1) {
            let (res, over) = (*a).overflowing_add(l);
            *a = res;
            if over {
                l = 1;
            } else {
                break;
            }
        }
    }

    fn process_block(&mut self, block: &GenericArray<u8, U64>, msg_len: u8) {
        let n = self.n;
        let block = unsafe { &*(block.as_ptr() as *const [u8; 64]) };
        self.g(&n, block);
        self.update_n(msg_len);
        self.update_sigma(block);
    }
}

#[derive(Clone)]
pub struct Streebog<DigestSize: ArrayLength<u8> + Copy> {
    buffer: BlockBuffer<U64>,
    state: StreebogState,
    // Phantom data to tie digest size to the struct
    digest_size: PhantomData<DigestSize>,
}

impl<N> Default for Streebog<N>  where N: ArrayLength<u8> + Copy {
    fn default() -> Self {
        let h = match N::to_usize() {
            64 => [0u8; 64],
            32 => [1u8; 64],
            _ => unreachable!()
        };
        Streebog {
            buffer: Default::default(),
            state: StreebogState { h, n: [0u8; 64], sigma: [0u8; 64] },
            digest_size: Default::default(),
        }
    }
}


impl<N> BlockInput for Streebog<N>  where N: ArrayLength<u8> + Copy {
    type BlockSize = U64;
}

impl<N> Input for Streebog<N>  where N: ArrayLength<u8> + Copy {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let self_state = &mut self.state;
        self.buffer.input(input.as_ref(),
            |d| self_state.process_block(d, BLOCK_SIZE as u8));
    }
}

impl<N> FixedOutput for Streebog<N>  where N: ArrayLength<u8> + Copy {
    type OutputSize = N;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        let mut self_state = self.state;
        let pos = self.buffer.position();

        let block = self.buffer.pad_with::<ZeroPadding>()
            .expect("we never use input_lazy");
        block[pos] = 1;
        self_state.process_block(block, pos as u8);

        let n = self_state.n;
        self_state.g(&[0u8; 64], &n);
        let sigma = self_state.sigma;
        self_state.g(&[0u8; 64], &sigma);

        let n = BLOCK_SIZE - Self::OutputSize::to_usize();
        GenericArray::clone_from_slice(&self_state.h[n..])
    }
}

impl<N> Reset for Streebog<N>  where N: ArrayLength<u8> + Copy {
    fn reset(&mut self) {
        self.buffer.reset();
        self.state.h = match N::to_usize() {
            64 => [0u8; 64],
            32 => [1u8; 64],
            _ => unreachable!()
        };
        self.state.n = [0; 64];
        self.state.sigma = [0; 64];
    }
}

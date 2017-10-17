#![cfg_attr(feature = "cargo-clippy", allow(needless_range_loop, inline_always))]

use digest;
use block_buffer::{BlockBuffer, ZeroPadding};
use generic_array::typenum::{Unsigned, U64};
use generic_array::{GenericArray, ArrayLength};
use byte_tools::{write_u64v_le, copy_memory};
use core::marker::PhantomData;

use consts::{BLOCK_SIZE, C};
use table::SHUFFLED_LIN_TABLE;

type Block = GenericArray<u8, U64>;

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

    write_u64v_le(h, &buf);
}

impl StreebogState {
    fn g(&mut self, n: &Block, m: &Block) {
        let mut key = Block::default();
        let mut block = Block::default();

        copy_memory(&self.h, &mut key);
        copy_memory(m, &mut block);

        lps(&mut key, n);

        for i in 0..12 {
            lps(&mut block, &key);
            lps(&mut key, Block::from_slice(&C[i]));
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

    fn process_block(&mut self, block: &Block, msg_len: u8) {
        let n = self.n;
        self.g(&n, block);
        self.update_n(msg_len);
        self.update_sigma(block);
    }
}

#[derive(Copy, Clone)]
pub struct Streebog<DigestSize: ArrayLength<u8> + Copy> {
    buffer: BlockBuffer<U64>,
    state: StreebogState,
    // Phantom data to tie digest size to the struct
    digest_size: PhantomData<DigestSize>,
}

impl<N> Default for Streebog<N>  where N: ArrayLength<u8> + Copy {
    fn default() -> Self {
        let h = match N::to_usize() {
            64 => Block::default(),
            32 => {
                let mut block = Block::default();
                for x in block.iter_mut() { *x = 1 }
                block
            },
            _ => unreachable!()
        };
        Streebog {
            buffer: Default::default(),
            state: StreebogState{
                h: h,
                n: Block::default(),
                sigma: Block::default(),
            },
            digest_size: Default::default(),
        }
    }
}


impl<N> digest::BlockInput for Streebog<N>  where N: ArrayLength<u8> + Copy {
    type BlockSize = U64;
}

impl<N> digest::Input for Streebog<N>  where N: ArrayLength<u8> + Copy {
    fn process(&mut self, input: &[u8]) {
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &Block| {
            self_state.process_block(d, BLOCK_SIZE as u8);
        });
    }
}

impl<N> digest::FixedOutput for Streebog<N>  where N: ArrayLength<u8> + Copy {
    type OutputSize = N;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        let self_state = &mut self.state;
        let pos = self.buffer.position();

        let block = self.buffer.pad_with::<ZeroPadding>();
        block[pos] = 1;
        self_state.process_block(block, pos as u8);

        let n = self_state.n;
        self_state.g(&Block::default(), &n);
        let sigma = self_state.sigma;
        self_state.g(&Block::default(), &sigma);

        let mut buf = GenericArray::default();
        let n = BLOCK_SIZE - Self::OutputSize::to_usize();
        buf.copy_from_slice(&self_state.h[n..]);
        buf
    }
}

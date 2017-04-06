use digest;
use digest_buffer::DigestBuffer;
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
        let mut over = 0u16;
        for (a, b) in self.sigma.iter_mut().zip(m.iter()) {
            let res = (*a as u16) + (*b as u16) + over;
            *a = (res & 0xff) as u8;
            over = res >> 8;
        }
    }

    fn update_n(&mut self, m_len: u8) {
        let res = (self.n[0] as u16) + ((m_len as u16) << 3);
        self.n[0] = (res & 0xff) as u8;
        let mut over = res >> 8;

        for a in self.n.iter_mut().skip(1) {
            let res = (*a as u16) + over;
            *a = (res & 0xff) as u8;
            over = res >> 8;
            if over == 0 { return; }
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
    buffer: DigestBuffer<U64>,
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


impl<N> digest::Input for Streebog<N>  where N: ArrayLength<u8> + Copy {
    type BlockSize = U64;

    fn digest(&mut self, input: &[u8]) {
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

        let msg_len = self.buffer.position() as u8;
        self.buffer.next(1)[0] = 1;
        self.buffer.zero_until(BLOCK_SIZE);
        let block = self.buffer.full_buffer();

        self_state.process_block(block, msg_len);


        let n = self_state.n;
        self_state.g(&Block::default(), &n);
        let sigma = self_state.sigma;
        self_state.g(&Block::default(), &sigma);

        let mut buf = GenericArray::default();
        let n = BLOCK_SIZE - Self::OutputSize::to_usize();
        copy_memory(&self_state.h[n..], &mut buf);
        buf
    }
}

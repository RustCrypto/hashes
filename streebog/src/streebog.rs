use digest::Digest;
use digest_buffer::DigestBuffer;
use generic_array::typenum::{Unsigned, U64};
use generic_array::{GenericArray, ArrayLength};
use byte_tools::{write_u64v_le, copy_memory};
use core::marker::PhantomData;

use consts::{BLOCK_SIZE, C};
use table::SHUFFLED_LIN_TABLE;

type Block = [u8; BLOCK_SIZE];

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

    for i in 0..8 {
        for j in 0..8 {
            let b = h[i + 8*j] as usize;
            buf[i] ^= SHUFFLED_LIN_TABLE[j][b];
        }
    }

    write_u64v_le(h, &buf);
}

impl StreebogState {
    fn g(&mut self, n: &Block, m: &[u8]) {
        let mut key = [0u8; BLOCK_SIZE];
        let mut block = [0u8; BLOCK_SIZE];

        copy_memory(&self.h, &mut key);
        copy_memory(m, &mut block);

        lps(&mut key, n);

        for i in 0..12 {
            lps(&mut block, &key);
            lps(&mut key, &C[i]);
        }

        for i in 0..64 {
            self.h[i] ^= block[i] ^ key[i]  ^ m[i];
        }
    }

    fn update_sigma(&mut self, m: &[u8]) {
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

    fn process_block(&mut self, block: &[u8], msg_len: u8) {
        assert!(block.len() == BLOCK_SIZE);
        let n = self.n;
        self.g(&n, block);
        self.update_n(msg_len);
        self.update_sigma(block);
    }
}

pub struct Streebog<DigestSize: ArrayLength<u8> + Copy> {
    buffer: DigestBuffer<U64>,
    state: StreebogState,
    // Phantom data to tie digest size to the struct
    digest_size: PhantomData<DigestSize>,
}

impl<N> Streebog<N> where N: ArrayLength<u8> + Copy {
    pub fn new() -> Streebog<N> {
        let h = match N::to_usize() {
            64 => [0; BLOCK_SIZE],
            32 => [1; BLOCK_SIZE],
            _ => panic!("Unexpected block size parameter")
        };
        Streebog {
            buffer: Default::default(),
            state: StreebogState{
                h: h,
                n: [0; BLOCK_SIZE],
                sigma: [0; BLOCK_SIZE],
            },
            digest_size: Default::default(),
        }
    }
}

impl<N> Default for Streebog<N>  where N: ArrayLength<u8> + Copy {
    fn default() -> Self { Self::new() }
}


impl<N> Digest for Streebog<N>  where N: ArrayLength<u8> + Copy {
    type OutputSize = N;
    type BlockSize = U64;

    fn input(&mut self, input: &[u8]) {
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &[u8]| {
            self_state.process_block(d, 64);
        });
    }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        let self_state = &mut self.state;
        let buf = self.buffer.current_buffer();

        let mut block = [0u8; BLOCK_SIZE];
        copy_memory(&buf, &mut block[..buf.len()]);
        block[buf.len()] = 1;

        self_state.process_block(&block, buf.len() as u8);

        let n = self_state.n;
        self_state.g(&[0u8; BLOCK_SIZE], &n);
        let sigma = self_state.sigma;
        self_state.g(&[0u8; BLOCK_SIZE], &sigma);

        let mut out = GenericArray::new();

        let n = BLOCK_SIZE - Self::OutputSize::to_usize();
        copy_memory(&self_state.h[n..], &mut out);
        
        out
    }
}

//! Streebog (GOST R 34.11-2012)

use block_buffer::{block_padding::ZeroPadding, BlockBuffer};
use core::marker::PhantomData;
use digest::consts::U64;
use digest::generic_array::{ArrayLength, GenericArray};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

use crate::consts::{BLOCK_SIZE, C};
use crate::table::SHUFFLED_LIN_TABLE;

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
            let b = h[2 * i + 8 * j] as usize;
            buf[2 * i] ^= SHUFFLED_LIN_TABLE[j][b];
            let b = h[2 * i + 1 + 8 * j] as usize;
            buf[2 * i + 1] ^= SHUFFLED_LIN_TABLE[j][b];
        }
    }

    for (chunk, v) in h.chunks_exact_mut(8).zip(buf.iter()) {
        chunk.copy_from_slice(&v.to_le_bytes());
    }
}

impl StreebogState {
    fn g(&mut self, n: &Block, m: &Block) {
        let mut key = [0u8; 64];
        let mut block = [0u8; 64];

        key.copy_from_slice(&self.h);
        block.copy_from_slice(m);

        lps(&mut key, n);

        #[allow(clippy::needless_range_loop)]
        for i in 0..12 {
            lps(&mut block, &key);
            lps(&mut key, &C[i]);
        }

        for i in 0..64 {
            self.h[i] ^= block[i] ^ key[i] ^ m[i];
        }
    }

    fn update_sigma(&mut self, m: &Block) {
        let mut carry = 0;
        for (a, b) in self.sigma.iter_mut().zip(m.iter()) {
            carry = (*a as u16) + (*b as u16) + (carry >> 8);
            *a = (carry & 0xFF) as u8;
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
        #[allow(unsafe_code)]
        let block = unsafe { &*(block.as_ptr() as *const [u8; 64]) };
        let n = self.n;
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

impl<N> Default for Streebog<N>
where
    N: ArrayLength<u8> + Copy,
{
    fn default() -> Self {
        let h = match N::to_usize() {
            64 => [0u8; 64],
            32 => [1u8; 64],
            _ => unreachable!(),
        };
        Streebog {
            buffer: Default::default(),
            state: StreebogState {
                h,
                n: [0u8; 64],
                sigma: [0u8; 64],
            },
            digest_size: Default::default(),
        }
    }
}

impl<N> BlockInput for Streebog<N>
where
    N: ArrayLength<u8> + Copy,
{
    type BlockSize = U64;
}

impl<N> Update for Streebog<N>
where
    N: ArrayLength<u8> + Copy,
{
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let s = &mut self.state;
        self.buffer
            .input_block(input.as_ref(), |d| s.process_block(d, BLOCK_SIZE as u8));
    }
}

impl<N> FixedOutputDirty for Streebog<N>
where
    N: ArrayLength<u8> + Copy,
{
    type OutputSize = N;

    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, N>) {
        let mut self_state = self.state;
        let pos = self.buffer.position();

        let block = self
            .buffer
            .pad_with::<ZeroPadding>()
            .expect("we never use input_lazy");
        block[pos] = 1;
        self_state.process_block(block, pos as u8);

        let n = self_state.n;
        self_state.g(&[0u8; 64], &n);
        let sigma = self_state.sigma;
        self_state.g(&[0u8; 64], &sigma);

        let n = BLOCK_SIZE - Self::OutputSize::to_usize();
        out.copy_from_slice(&self_state.h[n..])
    }
}

impl<N> Reset for Streebog<N>
where
    N: ArrayLength<u8> + Copy,
{
    fn reset(&mut self) {
        self.buffer.reset();
        self.state.h = match N::to_usize() {
            64 => [0u8; 64],
            32 => [1u8; 64],
            _ => unreachable!(),
        };
        self.state.n = [0; 64];
        self.state.sigma = [0; 64];
    }
}

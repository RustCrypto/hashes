use core::convert::TryInto;
use digest::{block_buffer::BlockBuffer, consts::U64, generic_array::GenericArray};

use crate::consts::{BLOCK_SIZE, C};
use crate::table::SHUFFLED_LIN_TABLE;

type Block = [u8; 64];

#[derive(Copy, Clone)]
pub(crate) struct StreebogState {
    pub(crate) h: Block,
    pub(crate) n: [u64; 8],
    pub(crate) sigma: [u64; 8],
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

    *h = to_bytes(&buf);
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
        let t = from_bytes(m);
        let mut carry = 0;
        adc(&mut self.sigma[0], t[0], &mut carry);
        adc(&mut self.sigma[1], t[1], &mut carry);
        adc(&mut self.sigma[2], t[2], &mut carry);
        adc(&mut self.sigma[3], t[3], &mut carry);
        adc(&mut self.sigma[4], t[4], &mut carry);
        adc(&mut self.sigma[5], t[5], &mut carry);
        adc(&mut self.sigma[6], t[6], &mut carry);
        adc(&mut self.sigma[7], t[7], &mut carry);
    }

    fn update_n(&mut self, len: u64) {
        let mut carry = 0;
        // note: `len` can not be bigger than block size,
        // so `8*len` will never overflow
        adc(&mut self.n[0], 8 * len, &mut carry);
        adc(&mut self.n[1], 0, &mut carry);
        adc(&mut self.n[2], 0, &mut carry);
        adc(&mut self.n[3], 0, &mut carry);
        adc(&mut self.n[4], 0, &mut carry);
        adc(&mut self.n[5], 0, &mut carry);
        adc(&mut self.n[6], 0, &mut carry);
        adc(&mut self.n[7], 0, &mut carry);
    }

    fn compress(&mut self, block: &GenericArray<u8, U64>, msg_len: u64) {
        let block = unsafe { &*(block.as_ptr() as *const [u8; 64]) };
        self.g(&to_bytes(&self.n), block);
        self.update_n(msg_len);
        self.update_sigma(block);
    }

    pub(crate) fn update_blocks(&mut self, blocks: &[GenericArray<u8, U64>]) {
        for block in blocks {
            self.compress(block, BLOCK_SIZE as u64);
        }
    }

    pub(crate) fn finalize(&mut self, buffer: &mut BlockBuffer<U64>) {
        let pos = buffer.get_pos();
        // note that it's guaranteed that `compress` will be called only once
        buffer.digest_pad(1, &[], |b| self.compress(b, pos as u64));
        self.g(&[0u8; 64], &to_bytes(&self.n));
        self.g(&[0u8; 64], &to_bytes(&self.sigma));
    }
}

#[inline(always)]
fn adc(a: &mut u64, b: u64, carry: &mut u64) {
    let ret = (*a as u128) + (b as u128) + (*carry as u128);
    *a = ret as u64;
    *carry = (ret >> 64) as u64;
}

#[inline(always)]
fn to_bytes(b: &[u64; 8]) -> Block {
    let mut t = [0; 64];
    for (chunk, v) in t.chunks_exact_mut(8).zip(b.iter()) {
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    t
}

#[inline(always)]
fn from_bytes(b: &Block) -> [u64; 8] {
    let mut t = [0u64; 8];
    for (v, chunk) in t.iter_mut().zip(b.chunks_exact(8)) {
        *v = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    t
}

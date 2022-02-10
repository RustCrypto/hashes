use core::{convert::TryInto, fmt};
use digest::{
    block_buffer::Eager,
    consts::U64,
    core_api::{
        AlgorithmName, Block as GenBlock, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser,
        TruncSide, UpdateCore, VariableOutputCore,
    },
    HashMarker, InvalidOutputSize, Output,
};

use crate::consts::{BLOCK_SIZE, C};
use crate::table::SHUFFLED_LIN_TABLE;

type Block = [u8; 64];

/// Core block-level Streebog hasher with variable output size.
///
/// Supports initialization only for 32 and 64 byte output sizes,
/// i.e. 256 and 512 bits respectively.
#[derive(Clone)]
pub struct StreebogVarCore {
    h: Block,
    n: [u64; 8],
    sigma: [u64; 8],
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

impl StreebogVarCore {
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

    fn compress(&mut self, block: &[u8; 64], msg_len: u64) {
        self.g(&to_bytes(&self.n), block);
        self.update_n(msg_len);
        self.update_sigma(block);
    }
}

impl HashMarker for StreebogVarCore {}

impl BlockSizeUser for StreebogVarCore {
    type BlockSize = U64;
}

impl BufferKindUser for StreebogVarCore {
    type BufferKind = Eager;
}

impl UpdateCore for StreebogVarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[GenBlock<Self>]) {
        for block in blocks {
            self.compress(block.as_ref(), BLOCK_SIZE as u64);
        }
    }
}

impl OutputSizeUser for StreebogVarCore {
    type OutputSize = U64;
}

impl VariableOutputCore for StreebogVarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let h = match output_size {
            32 => [1; 64],
            64 => [0; 64],
            _ => return Err(InvalidOutputSize),
        };
        let (n, sigma) = Default::default();
        Ok(Self { h, n, sigma })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        let block = buffer.pad_with_zeros();
        block[pos] = 1;
        self.compress(block.as_ref(), pos as u64);
        self.g(&[0u8; 64], &to_bytes(&self.n));
        self.g(&[0u8; 64], &to_bytes(&self.sigma));
        out.copy_from_slice(&self.h);
    }
}

impl AlgorithmName for StreebogVarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Streebog")
    }
}

impl fmt::Debug for StreebogVarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreebogVarCore { ... }")
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

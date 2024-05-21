use core::fmt;
use digest::{
    array::Array,
    block_buffer::Eager,
    consts::{U192, U64},
    core_api::{
        AlgorithmName, Block as GenBlock, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser,
        TruncSide, UpdateCore, VariableOutputCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    HashMarker, InvalidOutputSize, Output,
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

use crate::consts::{BLOCK_SIZE, C64, SHUFFLED_LIN_TABLE};

type Block = [u8; 64];

/// Core block-level Streebog hasher with variable output size.
///
/// Supports initialization only for 32 and 64 byte output sizes,
/// i.e. 256 and 512 bits respectively.
#[derive(Clone)]
pub struct StreebogVarCore {
    h: [u64; 8],
    n: [u64; 8],
    sigma: [u64; 8],
}

#[inline(always)]
fn lps(h: &mut [u64; 8], n: &[u64; 8]) {
    for i in 0..8 {
        h[i] ^= n[i];
    }

    let mut buf = [0u64; 8];
    #[allow(clippy::needless_range_loop)]
    for i in 0..8 {
        for j in 0..8 {
            let idx = (h[j] >> (8 * i) & 0xff) as usize;
            buf[i] ^= SHUFFLED_LIN_TABLE[j][idx];
        }
    }

    *h = buf;
}

fn g(h: &mut [u64; 8], n: &[u64; 8], m: &[u64; 8]) {
    let mut key = *h;
    let mut block = *m;

    lps(&mut key, n);

    for c in &C64 {
        lps(&mut block, &key);
        lps(&mut key, c);
    }

    for i in 0..8 {
        h[i] ^= block[i] ^ key[i] ^ m[i];
    }
}

impl StreebogVarCore {
    fn update_sigma(&mut self, m: &[u64; 8]) {
        let mut carry = 0;
        adc(&mut self.sigma[0], m[0], &mut carry);
        adc(&mut self.sigma[1], m[1], &mut carry);
        adc(&mut self.sigma[2], m[2], &mut carry);
        adc(&mut self.sigma[3], m[3], &mut carry);
        adc(&mut self.sigma[4], m[4], &mut carry);
        adc(&mut self.sigma[5], m[5], &mut carry);
        adc(&mut self.sigma[6], m[6], &mut carry);
        adc(&mut self.sigma[7], m[7], &mut carry);
    }

    fn update_n(&mut self, len: u64) {
        let mut carry = 0;
        // note: `len` can not be bigger than block size,
        // so `8 * len` will never overflow
        let bits_len = 8 * len;
        adc(&mut self.n[0], bits_len, &mut carry);
        adc(&mut self.n[1], 0, &mut carry);
        adc(&mut self.n[2], 0, &mut carry);
        adc(&mut self.n[3], 0, &mut carry);
        adc(&mut self.n[4], 0, &mut carry);
        adc(&mut self.n[5], 0, &mut carry);
        adc(&mut self.n[6], 0, &mut carry);
        adc(&mut self.n[7], 0, &mut carry);
    }

    fn compress(&mut self, block: &[u8; 64], msg_len: u64) {
        let block = from_bytes(block);
        g(&mut self.h, &self.n, &block);
        self.update_n(msg_len);
        self.update_sigma(&block);
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
            32 => [0x0101_0101_0101_0101; 8],
            64 => [0; 8],
            _ => return Err(InvalidOutputSize),
        };
        let (n, sigma) = Default::default();
        Ok(Self { h, n, sigma })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = 1;
        self.compress(block.as_ref(), pos as u64);
        g(&mut self.h, &[0u64; 8], &self.n);
        g(&mut self.h, &[0u64; 8], &self.sigma);
        out.copy_from_slice(&to_bytes(&self.h));
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

impl Drop for StreebogVarCore {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.h.zeroize();
            self.n.zeroize();
            self.sigma.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for StreebogVarCore {}

impl SerializableState for StreebogVarCore {
    type SerializedStateSize = U192;

    fn serialize(&self) -> SerializedState<Self> {
        let ser_h: Array<u8, U64> = to_bytes(&self.h).into();
        let ser_n: Array<u8, U64> = to_bytes(&self.n).into();
        let ser_sigma: Array<u8, U64> = to_bytes(&self.sigma).into();
        ser_h.concat(ser_n).concat(ser_sigma)
    }

    fn deserialize(ser_state: &SerializedState<Self>) -> Result<Self, DeserializeStateError> {
        let (ser_h, rem) = ser_state.split::<U64>();
        let (ser_n, ser_sigma) = rem.split::<U64>();

        Ok(Self {
            h: from_bytes(&ser_h.into()),
            n: from_bytes(&ser_n.into()),
            sigma: from_bytes(&ser_sigma.into()),
        })
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

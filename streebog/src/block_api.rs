use core::fmt;
use digest::{
    HashMarker, InvalidOutputSize, Output,
    array::Array,
    block_api::{
        AlgorithmName, Block as GenBlock, BlockSizeUser, Buffer, BufferKindUser, Eager,
        OutputSizeUser, TruncSide, UpdateCore, VariableOutputCore,
    },
    consts::{U64, U192},
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
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
            let idx = ((h[j] >> (8 * i)) & 0xff) as usize;
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
    #[inline(always)]
    fn update_sigma(&mut self, m: &[u64; 8]) {
        let mut carry = false;
        #[allow(clippy::needless_range_loop)]
        for i in 0..8 {
            adc(&mut self.sigma[i], m[i], &mut carry);
        }
    }

    #[inline(always)]
    fn update_n(&mut self, len: u64) {
        let mut carry = false;
        // Note: `len` can not be bigger than block size, so `8 * len` never overflows
        adc(&mut self.n[0], 8 * len, &mut carry);
        for i in 1..8 {
            adc(&mut self.n[i], 0, &mut carry);
        }
    }

    #[inline(always)]
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

// This function mirrors implementation of the `carrying_add` method:
// https://github.com/rust-lang/rust/blob/9cdfe28/library/core/src/num/uint_macros.rs#L2060-L2066
#[inline(always)]
fn adc(v1: &mut u64, v2: u64, carry: &mut bool) {
    let (a, b) = v1.overflowing_add(v2);
    let (c, d) = a.overflowing_add(*carry as u64);
    *v1 = c;
    *carry = b || d;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_carry_propagates_to_top_limb() {
        let mut core = StreebogVarCore {
            h: [0u64; 8],
            n: [0u64; 8],
            sigma: [0u64; 8],
        };
        core.n[0] = u64::MAX - 511;
        for i in 1..=6 {
            core.n[i] = u64::MAX;
        }
        core.n[7] = 0;
        core.update_n(64);
        for i in 0..=6 {
            assert_eq!(core.n[i], 0);
        }
        assert_eq!(core.n[7], 1);
    }

    #[test]
    fn counter_zero_len_no_change() {
        let mut core = StreebogVarCore {
            h: [0u64; 8],
            n: [1, 2, 3, 4, 5, 6, 7, 8],
            sigma: [0u64; 8],
        };
        let before = core.n;
        core.update_n(0);
        assert_eq!(core.n, before);
    }
}

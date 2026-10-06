use crate::U512;
use core::fmt;
use digest::{
    HashMarker, InvalidOutputSize, Output,
    array::Array,
    block_api::{
        AlgorithmName, Block as GenBlock, BlockSizeUser, Buffer, BufferKindUser, Eager,
        OutputSizeUser, TruncSide, UpdateCore, VariableOutputCore,
    },
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U64, U192},
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

use crate::consts::{BLOCK_SIZE, C64, SHUFFLED_LIN_TABLE};

/// Core block-level Streebog hasher with variable output size.
///
/// Supports initialization only for 32 and 64 byte output sizes,
/// i.e. 256 and 512 bits respectively.
#[derive(Clone)]
pub struct StreebogVarCore {
    h: U512,
    n: U512,
    sigma: U512,
}

#[inline(always)]
fn lps(h: &mut U512, n: &U512) {
    let t = *h ^ n;

    *h = U512::ZERO;
    #[allow(clippy::needless_range_loop)]
    for i in 0..8 {
        for j in 0..8 {
            let idx = ((t.0[j] >> (8 * i)) & 0xff) as usize;
            h.0[i] ^= SHUFFLED_LIN_TABLE[j][idx];
        }
    }
}

fn g(h: &mut U512, n: &U512, m: &U512) {
    let mut key = *h;
    let mut block = *m;

    lps(&mut key, n);

    for c in &C64 {
        lps(&mut block, &key);
        lps(&mut key, c);
    }

    *h ^= block;
    *h ^= key;
    *h ^= m;
}

impl StreebogVarCore {
    #[inline(always)]
    fn compress(&mut self, block: &[u8; 64], msg_len: u64) {
        let block = U512::from_bytes(block);
        g(&mut self.h, &self.n, &block);
        // `msg_len` can not be bigger than block size, so `8 * len` never overflows
        self.n += 8 * msg_len;
        self.sigma += block;
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
            32 => U512([0x0101_0101_0101_0101; 8]),
            64 => U512::ZERO,
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
        g(&mut self.h, &U512::ZERO, &self.n);
        g(&mut self.h, &U512::ZERO, &self.sigma);

        out.0 = self.h.to_bytes();
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
        let ser_h: Array<u8, U64> = self.h.to_bytes().into();
        let ser_n: Array<u8, U64> = self.n.to_bytes().into();
        let ser_sigma: Array<u8, U64> = self.sigma.to_bytes().into();
        ser_h.concat(ser_n).concat(ser_sigma)
    }

    fn deserialize(ser_state: &SerializedState<Self>) -> Result<Self, DeserializeStateError> {
        let (ser_h, rem) = ser_state.split::<U64>();
        let (ser_n, ser_sigma) = rem.split::<U64>();

        Ok(Self {
            h: U512::from_bytes(&ser_h.into()),
            n: U512::from_bytes(&ser_n.into()),
            sigma: U512::from_bytes(&ser_sigma.into()),
        })
    }
}

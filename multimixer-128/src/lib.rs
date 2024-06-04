use core::fmt;
use std::io::Read;

use digest::crypto_common::{InvalidLength, Key, KeyInit, KeySizeUser};
pub use digest::{self, Digest};

use digest::typenum::{array, Unsigned};
use digest::{
    array::Array,
    consts::{U256, U32, U64, U8},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, BufferKindUser, CoreWrapper, FixedOutputCore,
        UpdateCore,
    },
    HashMarker, OutputSizeUser, Reset,
};

pub struct MultimixerCore {
    x: [u32; 4usize],
    y: [u32; 4usize],
    h: [u32; 4usize],
    a: [u32; 4usize],
    b: [u32; 4usize],
    p: [u32; 4usize],
    q: [u32; 4usize],
    key: [u8; 32usize],
    block_sum: [u64; 8usize],
}

pub type Multimixer = CoreWrapper<MultimixerCore>;

impl MultimixerCore {
    fn compress(&mut self, message_block: &Block<Self>) {
        //self.x[0] = message_block & 0xffffff_000000_000000_000000_000000_000000_000000_000000;
        for i in 0..4 {
            self.x[i] = u32::from_be_bytes([
                message_block[0 + i * 4],
                message_block[1 + i * 4],
                message_block[2 + i * 4],
                message_block[3 + i * 4],
            ]);
            self.y[i] = u32::from_be_bytes([
                message_block[16 + i * 4],
                message_block[17 + i * 4],
                message_block[18 + i * 4],
                message_block[19 + i * 4],
            ]);
        }
        //TODO: Implement key and abpq
    }
}

impl KeySizeUser for MultimixerCore {
    type KeySize = U32;
}

impl KeyInit for MultimixerCore {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key).expect("Key has correct length")
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() != <Self as KeySizeUser>::KeySize::USIZE {
            return Err(InvalidLength);
        }
        let mut s = Self {
            x: [0; 4],
            y: [0; 4],
            h: [0; 4],
            a: [0; 4],
            b: [0; 4],
            p: [0; 4],
            q: [0; 4],
            block_sum: [0; 8],
            key: [0; 32],
        };
        s.key.clone_from_slice(&key);
        Ok(s)
    }
}

impl HashMarker for MultimixerCore {}

impl BlockSizeUser for MultimixerCore {
    fn block_size() -> usize {
        32usize
    }

    type BlockSize = U32;
}

impl BufferKindUser for MultimixerCore {
    type BufferKind = digest::block_buffer::Eager;
}

impl OutputSizeUser for MultimixerCore {
    type OutputSize = U8;

    fn output_size() -> usize {
        8usize
    }
}

impl UpdateCore for MultimixerCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.compress(block);
        }
    }
}

impl FixedOutputCore for MultimixerCore {
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut digest::core_api::Buffer<Self>,
        out: &mut digest::Output<Self>,
    ) {
        let pos = buffer.get_pos();
        let rem = buffer.remaining() as u8;
        let mut block = buffer.pad_with_zeros();
        block[pos..].iter_mut().for_each(|b| *b = rem);

        self.compress(&block);
    }
}

/*
impl Default for MultimixerCore {
    fn default() -> Self {
        Self {
            x: [0; 4usize],
            y: [0; 4usize],
            h: [0; 4usize],
            a: [0; 4usize],
            b: [0; 4usize],
            p: [0; 4usize],
            q: [0; 4usize],
            block_sum: [0; 8usize],
        }
    }
}
impl Reset for MultimixerCore {
    fn reset(&mut self) {}
}
*/

impl AlgorithmName for MultimixerCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Multimixer-128")
    }
}

impl fmt::Debug for MultimixerCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MultimixerCore { ... }")
    }
}
/*
impl Clone for MultimixerCore {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            h: self.h.clone(),
            a: self.a.clone(),
            b: self.b.clone(),
            p: self.p.clone(),
            q: self.q.clone(),
            key: self.key.clone(),
            block_sum: self.block_sum.clone(),
        }
    }
}
*/

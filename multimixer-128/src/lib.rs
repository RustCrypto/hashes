use core::fmt;

use digest::crypto_common::{InvalidLength, Key, KeyInit, KeySizeUser};
pub use digest::{self, Digest};

use digest::typenum::Unsigned;
use digest::{
    consts::{U32, U64},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, BufferKindUser, CoreWrapper, FixedOutputCore,
        UpdateCore,
    },
    HashMarker, OutputSizeUser,
};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

const BLOCKSIZE: usize = 32;

#[derive(Clone)]
pub struct MultimixerCore {
    key_blocks: Vec<Block<Self>>,
    block_sums: [u64; 8usize],
    block_index: usize,
    rng: Option<ChaCha8Rng>,
}

pub type Multimixer = CoreWrapper<MultimixerCore>;

impl MultimixerCore {
    fn compress(&mut self, message_block: &Block<Self>) {
        let mut x: [u32; 4usize] = [0u32; 4];
        //let mut h = [0u32; 4];
        let mut y = [0u32; 4];
        //let mut k = [0u32; 4];
        let mut a = [0u32; 4];
        let mut b = [0u32; 4];
        let mut p = [0u32; 4];
        let mut q = [0u32; 4];

        let (h, k) = if let Some(ref mut rng) = self.rng.as_mut() {
            let mut h = [0u32; 4];
            let mut k = [0u32; 4];

            for i in 0..4 {
                h[i] = rng.next_u32();
                k[i] = rng.next_u32();
            }
            (h, k)
        } else {
            let mut h = [0u32; 4];
            let mut k = [0u32; 4];
            for i in 0..4 {
                h[i] = u32::from_ne_bytes([
                    self.key_blocks[self.block_index][i * 4],
                    self.key_blocks[self.block_index][i * 4 + 1],
                    self.key_blocks[self.block_index][i * 4 + 2],
                    self.key_blocks[self.block_index][i * 4 + 3],
                ]);
                k[i] = u32::from_ne_bytes([
                    self.key_blocks[self.block_index][i * 4 + 16],
                    self.key_blocks[self.block_index][i * 4 + 17],
                    self.key_blocks[self.block_index][i * 4 + 18],
                    self.key_blocks[self.block_index][i * 4 + 19],
                ]);
            }
            (h, k)
        };

        for i in 0..4 {
            x[i] = u32::from_ne_bytes([
                message_block[0 + i * 4],
                message_block[1 + i * 4],
                message_block[2 + i * 4],
                message_block[3 + i * 4],
            ]);
            y[i] = u32::from_ne_bytes([
                message_block[16 + i * 4],
                message_block[17 + i * 4],
                message_block[18 + i * 4],
                message_block[19 + i * 4],
            ]);

            a[i] = x[i].wrapping_add(h[i]);
            b[i] = y[i].wrapping_add(k[i]);
        }

        for i in 0..4 {
            p[i] = a[i]
                .wrapping_add(a[(i + 1) % 4])
                .wrapping_add(a[(i + 2) % 4]);
            q[i] = b[(i + 1) % 4]
                .wrapping_add(b[(i + 2) % 4])
                .wrapping_add(b[(i + 3) % 4]);
        }

        let block_res = [
            a[0] as u64 * b[0] as u64,
            a[1] as u64 * b[1] as u64,
            a[2] as u64 * b[2] as u64,
            a[3] as u64 * b[3] as u64,
            p[0] as u64 * q[0] as u64,
            p[1] as u64 * q[1] as u64,
            p[2] as u64 * q[2] as u64,
            p[3] as u64 * q[3] as u64,
        ];

        for i in 0..self.block_sums.len() {
            self.block_sums[i] = self.block_sums[i].wrapping_add(block_res[i]);
        }

        self.block_index += 1;
    }

    fn finalize(&self, out: &mut digest::Output<Self>) {
        for (i, block) in self.block_sums.iter().enumerate() {
            let bytes = block.to_ne_bytes(); // Convert u64 to little-endian byte array
            for (j, &byte) in bytes.iter().enumerate() {
                out[i * 8 + j] = byte;
            }
        }
    }
}

impl KeySizeUser for MultimixerCore {
    type KeySize = U32;

    fn key_size() -> usize {
        Self::KeySize::USIZE
    }
}

impl KeyInit for MultimixerCore {
    //Uses the key to initialize ChaCha8Rng RNG and fills the key_blocks array
    fn new(key: &Key<Self>) -> Self {
        Self {
            block_sums: [0; 8],
            key_blocks: Vec::new(),
            block_index: 0,
            rng: Some(ChaCha8Rng::from_seed(
                key.as_slice()
                    .try_into()
                    .expect("Key needs to be able to use as seed."),
            )),
        }
    }

    //Uses key instead of RNG, needs to be same size as message.
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let key_block_size = <Self as KeySizeUser>::KeySize::USIZE;
        if key.len() % key_block_size != 0 {
            return Err(InvalidLength);
        }
        let mut s = Self {
            block_sums: [0; 8],
            key_blocks: Vec::new(),
            block_index: 0,
            rng: None,
        };

        for block in key.chunks(key_block_size) {
            let array: [u8; BLOCKSIZE] = block
                .try_into()
                .expect("Key chunk is not of length 32 bytes");
            s.key_blocks.push(array.into());
        }
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
    type OutputSize = U64;

    fn output_size() -> usize {
        64usize
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
        _buffer: &mut digest::core_api::Buffer<Self>,
        out: &mut digest::Output<Self>,
    ) {
        self.finalize(out);
    }
}

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

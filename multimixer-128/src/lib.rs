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

const BLOCKSIZE: usize = 32;

pub struct MultimixerCore {
    key_blocks: Vec<Block<Self>>,
    block_sums: [u64; 8usize],
    block_index: usize,
}

pub type Multimixer = CoreWrapper<MultimixerCore>;

impl MultimixerCore {
    fn compress(&mut self, message_block: &Block<Self>) {
        //self.x[0] = message_block & 0xffffff_000000_000000_000000_000000_000000_000000_000000;

        let mut x: [u32; 4usize] = [0u32; 4];
        let mut h = [0u32; 4];
        let mut y = [0u32; 4];
        let mut k = [0u32; 4];
        let mut a = [0u32; 4];
        let mut b = [0u32; 4];
        let mut p = [0u32; 4];
        let mut q = [0u32; 4];

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

        // let mut block_temp = [0u64; 8usize];
        // Update blk_temp with the results from Blk_res
        for i in 0..self.block_sums.len() {
            self.block_sums[i] = self.block_sums[i].wrapping_add(block_res[i]);
        }
        println!("block_sums: {:02x?}", self.block_sums);
        println!("x: {:x?}", x);
        println!("y: {:x?}", y);
        self.block_index += 1;
    }

    fn finalize(&self, out: &mut digest::Output<Self>) {
        for (i, block) in self.block_sums.iter().enumerate() {
            let bytes = block.to_le_bytes(); // Convert u64 to little-endian byte array
            for (j, &byte) in bytes.iter().enumerate() {
                out[i * 8 + j] = byte;
            }
        }
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
        let key_block_size = <Self as KeySizeUser>::KeySize::USIZE;
        if key.len() % key_block_size != 0 {
            return Err(InvalidLength);
        }
        let mut s = Self {
            block_sums: [0; 8],
            key_blocks: Vec::new(),
            block_index: 0,
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
        buffer: &mut digest::core_api::Buffer<Self>,
        out: &mut digest::Output<Self>,
    ) {
        //let pos = buffer.get_pos();
        //let rem = buffer.remaining() as u8;
        //let mut block = buffer.pad_with_zeros();
        //block[pos..].iter_mut().for_each(|b| *b = rem);

        //self.compress(&block);
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

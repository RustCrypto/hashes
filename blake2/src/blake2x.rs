use crate::Blake2Parameters;
use crate::Blake2bVarCore;
use digest::{
    ExtendableOutput, Update, XofReader,
    block_buffer::{LazyBuffer, ReadBuffer},
    consts::U64,
    core_api::{Buffer, BufferKindUser, UpdateCore, VariableOutputCore},
};

use super::{Blake2b512, BlockSizeUser, InvalidLength, Unsigned};

/// Blake2Xb root hasher
pub struct Blake2Xb {
    root_hasher: Blake2bVarCore,
    buffer: LazyBuffer<<Blake2b512 as BlockSizeUser>::BlockSize>,
    max_length: Option<u32>,
}

impl Blake2Xb {
    /// Create new instance using provided key.
    ///
    /// Setting key to `None` indicates unkeyed usage.
    ///
    /// # Errors
    ///
    /// If key is `Some`, then its length should not be zero or bigger
    /// than the block size. If this conditions is false the method will
    /// return an error.
    #[inline]
    pub fn new(key: Option<&[u8]>, max_length: Option<u32>) -> Result<Self, InvalidLength> {
        let kl = key.map_or(0, |k| k.len());
        let bs = <Blake2b512 as BlockSizeUser>::BlockSize::USIZE;
        if key.is_some() && kl == 0 || kl > bs {
            return Err(InvalidLength);
        }

        let params = Blake2Parameters {
            digest_length: 64,
            key_size: kl.try_into().unwrap(),
            fanout: 1,
            depth: 1,
            xof_digest_length: Some(max_length.unwrap_or(u32::MAX)),
            ..<_>::default()
        };
        let root_hasher = Blake2bVarCore::from_params(params);

        let mut hasher = Self {
            root_hasher,
            buffer: <_>::default(),
            max_length,
        };

        if let Some(k) = key {
            // Update state with key
            hasher.update(k);
            // Pad key with zeros
            let pad_len = 128 - kl;
            let padding = [0; 128];
            hasher.update(&padding[..pad_len]);
        }

        Ok(hasher)
    }
}

/// Finalized XOF instance over Blake2b
pub struct Blake2XbReader {
    h0: [u8; 64],
    buffer: ReadBuffer<<Self as BlockSizeUser>::BlockSize>,
    node_offset: u32,
    total_length: u32,
}

impl BlockSizeUser for Blake2XbReader {
    type BlockSize = U64;
}

impl BufferKindUser for Blake2XbReader {
    type BufferKind = <Blake2bVarCore as BufferKindUser>::BufferKind;
}

impl XofReader for Blake2XbReader {
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { buffer: buf, .. } = self;
        buf.read(buffer, |block| {
            let digest_length = 64.min(self.total_length - self.node_offset * 64) as u8;

            let mut hasher = Blake2bVarCore::from_params(Blake2Parameters {
                digest_length,
                leaf_length: 64,
                node_offset: self.node_offset as u64,
                xof_digest_length: Some(self.total_length),
                inner_length: 64,
                ..<_>::default()
            });

            self.node_offset += 1;

            hasher.finalize_variable_core(&mut Buffer::<Blake2bVarCore>::new(&self.h0), block);
        });
    }
}

#[cfg(feature = "std")]
impl std::io::Read for Blake2XbReader {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        XofReader::read(self, buf);
        Ok(buf.len())
    }
}

impl BlockSizeUser for Blake2Xb {
    type BlockSize = <Blake2bVarCore as BlockSizeUser>::BlockSize;
}

impl BufferKindUser for Blake2Xb {
    type BufferKind = <Blake2bVarCore as BufferKindUser>::BufferKind;
}

impl Update for Blake2Xb {
    fn update(&mut self, data: &[u8]) {
        let Self {
            root_hasher,
            buffer,
            ..
        } = self;
        buffer.digest_blocks(data, |blocks| root_hasher.update_blocks(blocks));
    }
}

impl ExtendableOutput for Blake2Xb {
    type Reader = Blake2XbReader;

    fn finalize_xof(self) -> Self::Reader {
        let mut m = <_>::default();
        let Self {
            mut root_hasher,
            mut buffer,
            max_length,
        } = self;
        root_hasher.finalize_variable_core(&mut buffer, &mut m);

        let mut h0 = [0; 64];
        h0.copy_from_slice(&m);

        Blake2XbReader {
            h0,
            buffer: <_>::default(),
            node_offset: 0,
            total_length: max_length.unwrap_or(u32::MAX),
        }
    }
}

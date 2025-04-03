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

pub struct Blake2bXReader {
    h0: [u8; 64],
    buffer: ReadBuffer<<Self as BlockSizeUser>::BlockSize>,
    node_offset: u32,
    total_length: u32,
}

impl BlockSizeUser for Blake2bXReader {
    type BlockSize = U64;
}

impl BufferKindUser for Blake2bXReader {
    type BufferKind = <Blake2bVarCore as BufferKindUser>::BufferKind;
}

impl XofReader for Blake2bXReader {
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
impl std::io::Read for Blake2bXReader {
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
    type Reader = Blake2bXReader;

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

        Blake2bXReader {
            h0,
            buffer: <_>::default(),
            node_offset: 0,
            total_length: max_length.unwrap_or(u32::MAX),
        }
    }
}

#[test]
fn test() {
    let seed = [
        0x72, 0x01, 0xa8, 0x01, 0xc4, 0xf9, 0x95, 0x7c, 0x76, 0x65, 0xc2, 0xfd, 0x42, 0x76, 0x1f,
        0x5d, 0xa6, 0xc0, 0x55, 0x51, 0xf1, 0x5c, 0x21, 0x53, 0x78, 0x8b, 0xa7, 0x0d, 0x95, 0x60,
        0xd7, 0xee,
    ];
    let mut b = crate::blake2xb(&seed[..]);

    let expected = [
        0x4b, 0xd4, 0x10, 0x91, 0x1b, 0xf5, 0xdc, 0xb1, 0x99, 0x2e, 0xb7, 0x23, 0x83, 0x54, 0x98,
        0xda, 0xbf, 0x58, 0xce, 0x34, 0x82, 0x39, 0x3c, 0x2b, 0xd2, 0xaa, 0x3b, 0x79, 0xc4, 0xe2,
        0x2c, 0xb8, 0x06, 0xe6, 0x31, 0x65, 0x2e, 0x2a, 0xff, 0x3c, 0x33, 0x98, 0x64, 0x51, 0x2e,
        0xdd, 0xc1, 0xe0, 0x27, 0x17, 0xb2, 0xeb, 0xd4, 0x99, 0xa6, 0xe9, 0xe1, 0xb8, 0x96, 0x7d,
        0x23, 0x00, 0x54, 0xa4, 0x16, 0x58, 0xa3, 0xf4, 0xfe, 0x04, 0xb0, 0x62, 0x9f, 0xc8, 0xe6,
        0x9f, 0x6b, 0xf5, 0x1d, 0xe7, 0x59, 0x09, 0x0c, 0xe5, 0x4d, 0x82, 0xc0, 0xda, 0xda, 0xc9,
        0x21, 0xa3, 0x3f, 0x18, 0xb1, 0xb6, 0xbe, 0x8e, 0x9b, 0x12, 0x4d, 0x46, 0xf2, 0x6b, 0x9c,
        0xb0, 0xdb, 0xec, 0xae, 0x21, 0xf5, 0x04, 0x88, 0x6b, 0xc0, 0x75, 0x3e, 0x9e, 0x62, 0xd4,
        0x98, 0xdf, 0xb0, 0x18, 0xb3, 0x4a, 0x14, 0xd5, 0xfc, 0xee, 0xf4, 0xc0, 0xd9, 0x78, 0xe1,
        0xda, 0x27, 0xa0, 0x71, 0x56, 0x4d, 0x7e, 0xbd, 0x56, 0xfd, 0x09, 0x27, 0x65, 0x19, 0x9e,
        0x17, 0x91, 0xdd, 0xad, 0x7b, 0x60, 0x1d, 0x26, 0xce, 0x39, 0x26, 0x39, 0xad, 0x17, 0xc2,
        0xeb, 0x60, 0x7f, 0x9e, 0x82, 0x78, 0x2e, 0x5f, 0x72, 0x5d, 0x19, 0x69, 0xb6, 0xb4, 0xf0,
        0x8b, 0x91, 0x9f, 0xf4, 0xc7, 0xf4, 0x1c, 0x04, 0xa9, 0xb8, 0xee, 0x08,
    ];
    let mut buf = [0; 64 * 3];
    b.read(&mut buf);
    assert_eq!(expected, buf);
}

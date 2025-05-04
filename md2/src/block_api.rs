use core::fmt;
use digest::{
    HashMarker, Output,
    array::Array,
    block_buffer::Eager,
    consts::{U16, U48, U64},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
};

use crate::consts::S;

const STATE_LEN: usize = 48;

/// Core MD2 hasher state
#[derive(Clone)]
pub struct Md2Core {
    x: [u8; STATE_LEN],
    checksum: [u8; 16],
}

impl Md2Core {
    fn compress(&mut self, block: &[u8; 16]) {
        self.x[16..32].copy_from_slice(block);
        // Update state
        for j in 0..16 {
            self.x[32 + j] = self.x[16 + j] ^ self.x[j];
        }

        let mut t = 0u8;
        for j in 0..18u8 {
            for k in 0..STATE_LEN {
                self.x[k] ^= S[t as usize];
                t = self.x[k];
            }
            t = t.wrapping_add(j);
        }

        // Update checksum
        let mut l = self.checksum[15];
        for j in 0..16 {
            self.checksum[j] ^= S[(block[j] ^ l) as usize];
            l = self.checksum[j];
        }
    }
}

impl HashMarker for Md2Core {}

impl BlockSizeUser for Md2Core {
    type BlockSize = U16;
}

impl BufferKindUser for Md2Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Md2Core {
    type OutputSize = U16;
}

impl UpdateCore for Md2Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.compress(block.as_ref())
        }
    }
}

impl FixedOutputCore for Md2Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        let rem = buffer.remaining() as u8;
        let mut block = buffer.pad_with_zeros();
        block[pos..].iter_mut().for_each(|b| *b = rem);

        self.compress(block.as_ref());
        let checksum = self.checksum;
        self.compress(&checksum);
        out.copy_from_slice(&self.x[..16]);
    }
}

impl Default for Md2Core {
    #[inline]
    fn default() -> Self {
        Self {
            x: [0; STATE_LEN],
            checksum: Default::default(),
        }
    }
}

impl Reset for Md2Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Md2Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md2")
    }
}

impl fmt::Debug for Md2Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md2Core { ... }")
    }
}

impl Drop for Md2Core {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.x.zeroize();
            self.checksum.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for Md2Core {}

impl SerializableState for Md2Core {
    type SerializedStateSize = U64;

    fn serialize(&self) -> SerializedState<Self> {
        let checksum: Block<Self> = self.checksum.into();
        Array::<_, U48>::from(self.x).concat(checksum)
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_x, serialized_checksum) = serialized_state.split::<U48>();

        Ok(Self {
            x: *serialized_x.as_ref(),
            checksum: serialized_checksum.0,
        })
    }
}

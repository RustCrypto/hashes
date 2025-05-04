use core::fmt;
use digest::{
    HashMarker, InvalidOutputSize, Output,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser, TruncSide,
        UpdateCore, VariableOutputCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{Sum, U8, U32, U64, U128, Unsigned},
};

use crate::{compress_long, compress_short};

macro_rules! impl_variant {
    ($name:ident, $var:literal, $block_size:ty, $output_size:ty, $compress:ident) => {
        #[doc = "Lowest-level core hasher state of the Groestl "]
        #[doc = $var]
        #[doc = " variant."]
        #[derive(Clone)]
        pub struct $name {
            state: [u64; $compress::COLS],
            blocks_len: u64,
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                self.blocks_len += blocks.len() as u64;
                for block in blocks {
                    $compress::compress(&mut self.state, block.as_ref());
                }
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl VariableOutputCore for $name {
            const TRUNC_SIDE: TruncSide = TruncSide::Right;

            #[inline]
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size > Self::OutputSize::USIZE {
                    return Err(InvalidOutputSize);
                }
                let mut state = [0; $compress::COLS];
                state[$compress::COLS - 1] = 8 * output_size as u64;
                let blocks_len = 0;
                Ok(Self { state, blocks_len })
            }

            #[inline]
            fn finalize_variable_core(
                &mut self,
                buffer: &mut Buffer<Self>,
                out: &mut Output<Self>,
            ) {
                let blocks_len = if buffer.remaining() <= 8 {
                    self.blocks_len + 2
                } else {
                    self.blocks_len + 1
                };
                buffer.len64_padding_be(blocks_len, |block| {
                    $compress::compress(&mut self.state, block.as_ref())
                });
                let res = $compress::p(&self.state);
                let n = $compress::COLS / 2;
                for (chunk, v) in out.chunks_exact_mut(8).zip(res[n..].iter()) {
                    chunk.copy_from_slice(&v.to_be_bytes());
                }
            }
        }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("Groestl", $var))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    use digest::zeroize::Zeroize;
                    self.state.zeroize();
                    self.blocks_len.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $name {}

        impl SerializableState for $name {
            type SerializedStateSize = Sum<$block_size, U8>;

            fn serialize(&self) -> SerializedState<Self> {
                let mut serialized_state = SerializedState::<Self>::default();

                for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(8)) {
                    chunk.copy_from_slice(&val.to_le_bytes());
                }

                let bs = Self::block_size();
                serialized_state[bs..].copy_from_slice(&self.blocks_len.to_le_bytes());
                serialized_state
            }

            fn deserialize(
                serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                let (serialized_state, serialized_block_len) =
                    serialized_state.split::<$block_size>();

                let mut state = [0; $compress::COLS];
                for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(8)) {
                    *val = u64::from_le_bytes(chunk.try_into().unwrap());
                }

                let blocks_len = u64::from_le_bytes(*serialized_block_len.as_ref());

                Ok(Self { state, blocks_len })
            }
        }
    };
}

impl_variant!(GroestlShortVarCore, "Short", U64, U32, compress_short);
impl_variant!(GroestlLongVarCore, "Long", U128, U64, compress_long);

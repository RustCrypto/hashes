use core::fmt;
use digest::{
    HashMarker, Output,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{Sum, U8, U16, U20, U32, U40, U64, Unsigned},
};

macro_rules! impl_ripemd {
    (
        $name:ident, $mod:ident, $alg_width:expr, $doc_name:expr, $output_size:ty
    ) => {
        #[doc = "Core block-level"]
        #[doc = $doc_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        pub struct $name {
            h: [u32; crate::$mod::DIGEST_BUF_LEN],
            block_len: u64,
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = U64;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                // Assumes that `block_len` does not overflow
                self.block_len += blocks.len() as u64;
                for block in blocks {
                    crate::$mod::compress(&mut self.h, block.as_ref());
                }
            }
        }

        impl FixedOutputCore for $name {
            #[inline]
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                let bs = Self::BlockSize::U64;
                let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
                let mut h = self.h;
                buffer.len64_padding_le(bit_len, |block| {
                    crate::$mod::compress(&mut h, block.as_ref())
                });

                for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
                    chunk.copy_from_slice(&v.to_le_bytes());
                }
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    h: crate::$mod::H0,
                    block_len: 0,
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("Ripemd", $alg_width))
            }
        }

        impl fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("Ripemd", $alg_width, "Core { ... }"))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    use digest::zeroize::Zeroize;
                    self.h.zeroize();
                    self.block_len.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $name {}

        impl SerializableState for $name {
            type SerializedStateSize = Sum<crate::$mod::DigestBufByteLen, U8>;

            fn serialize(&self) -> SerializedState<Self> {
                let mut serialized_h = SerializedState::<Self>::default();

                for (val, chunk) in self.h.iter().zip(serialized_h.chunks_exact_mut(4)) {
                    chunk.copy_from_slice(&val.to_le_bytes());
                }

                serialized_h[crate::$mod::DigestBufByteLen::USIZE..]
                    .copy_from_slice(&self.block_len.to_le_bytes());
                serialized_h
            }

            fn deserialize(
                serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                let (serialized_h, serialized_block_len) =
                    serialized_state.split::<crate::$mod::DigestBufByteLen>();

                let mut h = [0; crate::$mod::DIGEST_BUF_LEN];
                for (val, chunk) in h.iter_mut().zip(serialized_h.chunks_exact(4)) {
                    *val = u32::from_le_bytes(chunk.try_into().unwrap());
                }

                let block_len = u64::from_le_bytes(*serialized_block_len.as_ref());

                Ok(Self { h, block_len })
            }
        }
    };
}

impl_ripemd!(Ripemd128Core, c128, "128", "RIPEMD-128", U16);
impl_ripemd!(Ripemd160Core, c160, "160", "RIPEMD-160", U20);
impl_ripemd!(Ripemd256Core, c256, "256", "RIPEMD-256", U32);
impl_ripemd!(Ripemd320Core, c320, "320", "RIPEMD-320", U40);

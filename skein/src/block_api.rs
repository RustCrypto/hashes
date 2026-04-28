use core::{fmt, marker::PhantomData};
use digest::{
    HashMarker, Output,
    array::ArraySize,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore, Lazy,
        OutputSizeUser, Reset, UpdateCore,
    },
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{Sum, U16, U32, U64, U128, Unsigned},
};
use threefish::{Threefish256, Threefish512, Threefish1024};

const VERSION: u64 = 1;
const ID_STRING_LE: u64 = 0x3341_4853;
const SCHEMA_VER: u64 = (VERSION << 32) | ID_STRING_LE;
const CFG_TREE_INFO_SEQUENTIAL: u64 = 0;
const T1_FLAG_FIRST: u64 = 1 << 62;
const T1_FLAG_FINAL: u64 = 1 << 63;
const T1_BLK_TYPE_CFG: u64 = 4 << 56;
const T1_BLK_TYPE_MSG: u64 = 48 << 56;
const T1_BLK_TYPE_OUT: u64 = 63 << 56;
const CFG_STR_LEN: usize = 4 * 8;

macro_rules! define_hasher {
    (
        $name:ident, $threefish:ident,
        $state_bytes:ty, $alg_name:expr
    ) => {
        #[doc = $alg_name]
        #[doc = " core hasher state"]
        #[derive(Clone)]
        pub struct $name<N: ArraySize> {
            t: [u64; 2],
            x: [u64; <$state_bytes>::USIZE / 8],
            _pd: PhantomData<N>,
        }

        impl<N: ArraySize> $name<N> {
            fn blank_state(t1: u64, x: [u64; <$state_bytes>::USIZE / 8]) -> Self {
                Self {
                    t: [0, t1],
                    x,
                    _pd: PhantomData,
                }
            }

            fn process_block(&mut self, block: &Block<Self>, byte_count_add: usize) {
                const STATE_WORDS: usize = <$state_bytes>::USIZE / 8;

                self.t[0] += byte_count_add as u64;
                let cipher = $threefish::new_with_tweak_u64(&self.x.into(), &self.t);

                let mut x = [0u64; STATE_WORDS];
                for (src, dst) in block.chunks_exact(8).zip(x.iter_mut()) {
                    *dst = u64::from_le_bytes(src.try_into().unwrap());
                }
                let t = x;

                cipher.encrypt_block_u64(&mut x);

                for i in 0..STATE_WORDS {
                    self.x[i] = t[i] ^ x[i];
                }
                self.t[1] &= !T1_FLAG_FIRST;
            }
        }

        impl<N> HashMarker for $name<N> where N: ArraySize {}

        impl<N: ArraySize> BlockSizeUser for $name<N> {
            type BlockSize = $state_bytes;
        }

        impl<N: ArraySize> BufferKindUser for $name<N> {
            type BufferKind = Lazy;
        }

        impl<N: ArraySize> OutputSizeUser for $name<N> {
            type OutputSize = N;
        }

        impl<N: ArraySize> UpdateCore for $name<N> {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.process_block(block, block.len())
                }
            }
        }

        impl<N: ArraySize> FixedOutputCore for $name<N> {
            #[inline]
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                self.t[1] |= T1_FLAG_FINAL;
                let pos = buffer.get_pos();
                let final_block = buffer.pad_with_zeros();
                self.process_block(&final_block, pos);

                // run Threefish in "counter mode" to generate output
                let flag = T1_FLAG_FIRST | T1_BLK_TYPE_OUT | T1_FLAG_FINAL;
                let mut block = Block::<Self>::default();
                for (i, chunk) in out.chunks_mut(block.len()).enumerate() {
                    let mut ctr = Self::blank_state(flag, self.x);

                    block[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    Self::process_block(&mut ctr, &block, 8);

                    for (src, dst) in ctr.x.iter().zip(chunk.chunks_mut(8)) {
                        dst.copy_from_slice(&src.to_le_bytes()[..dst.len()]);
                    }
                }
            }
        }

        impl<N: ArraySize> Default for $name<N> {
            fn default() -> Self {
                // build and process config block
                let mut state = Self::blank_state(
                    T1_FLAG_FIRST | T1_BLK_TYPE_CFG | T1_FLAG_FINAL,
                    Default::default(),
                );

                let mut cfg = Block::<Self>::default();
                cfg[..8].copy_from_slice(&SCHEMA_VER.to_le_bytes());
                cfg[8..16].copy_from_slice(&(N::to_u64() * 8).to_le_bytes());
                cfg[16..24].copy_from_slice(&CFG_TREE_INFO_SEQUENTIAL.to_le_bytes());

                state.process_block(&cfg, CFG_STR_LEN);

                // The chaining vars ctx->X are now initialized for the given hashBitLen.
                // Set up to process the data message portion of the hash (default)
                state.t = [0, T1_FLAG_FIRST | T1_BLK_TYPE_MSG];
                state
            }
        }

        impl<N: ArraySize> Reset for $name<N> {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl<N: ArraySize> AlgorithmName for $name<N> {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
            }
        }

        impl<N: ArraySize> fmt::Debug for $name<N> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, "{}<{}> {{ .. }}", stringify!($name), N::USIZE)
            }
        }

        impl<N: ArraySize> Drop for $name<N> {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    use digest::zeroize::Zeroize;
                    self.t.zeroize();
                    self.x.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl<N: ArraySize> digest::zeroize::ZeroizeOnDrop for $name<N> {}

        impl<N: ArraySize> SerializableState for $name<N> {
            type SerializedStateSize = Sum<$state_bytes, U16>;

            #[inline]
            fn serialize(&self) -> SerializedState<Self> {
                let mut dst = SerializedState::<Self>::default();
                let (t_dst, x_dst) = dst.split_at_mut(16);

                t_dst[..8].copy_from_slice(&self.t[0].to_le_bytes());
                t_dst[8..].copy_from_slice(&self.t[1].to_le_bytes());

                for (src, dst) in self.x.iter().zip(x_dst.chunks_exact_mut(8)) {
                    dst.copy_from_slice(&src.to_le_bytes());
                }

                dst
            }

            #[inline]
            fn deserialize(
                serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                let (t_src, x_src) = serialized_state.split_at(16);
                let t = core::array::from_fn(|i| {
                    let chunk = &t_src[8 * i..][..8];
                    u64::from_le_bytes(chunk.try_into().unwrap())
                });
                let x = core::array::from_fn(|i| {
                    let chunk = &x_src[8 * i..][..8];
                    u64::from_le_bytes(chunk.try_into().unwrap())
                });
                Ok(Self {
                    t,
                    x,
                    _pd: PhantomData,
                })
            }
        }
    };
}

define_hasher!(Skein256Core, Threefish256, U32, "Skein-256");
define_hasher!(Skein512Core, Threefish512, U64, "Skein-512");
define_hasher!(Skein1024Core, Threefish1024, U128, "Skein-1024");

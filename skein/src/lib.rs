#![no_std]

use block_buffer::{BlockBuffer, Lazy};
use cipher::BlockEncrypt;
use digest::generic_array::{
    typenum::{NonZero, PartialDiv, Unsigned, U128, U32, U64, U8},
    ArrayLength,
};
pub use digest::{generic_array::GenericArray, Digest};
use threefish::{Threefish1024, Threefish256, Threefish512};

/// N word buffer.
#[derive(Copy, Clone)]
union Block<N>
where
    N: ArrayLength<u8>,
    N: PartialDiv<U8>,
    <N as PartialDiv<U8>>::Output: ArrayLength<u64>,
    N::ArrayType: Copy,
    <<N as PartialDiv<U8>>::Output as ArrayLength<u64>>::ArrayType: Copy,
{
    bytes: GenericArray<u8, N>,
    words: GenericArray<u64, <N as PartialDiv<U8>>::Output>,
}

impl<N> Block<N>
where
    N: ArrayLength<u8>,
    N: PartialDiv<U8>,
    <N as PartialDiv<U8>>::Output: ArrayLength<u64>,
    N::ArrayType: Copy,
    <<N as PartialDiv<U8>>::Output as ArrayLength<u64>>::ArrayType: Copy,
{
    fn bytes(&mut self) -> &[u8] {
        self.as_byte_array().as_slice()
    }

    fn as_byte_array(&self) -> &GenericArray<u8, N> {
        unsafe { &self.bytes }
    }

    fn as_byte_array_mut(&mut self) -> &mut GenericArray<u8, N> {
        unsafe { &mut self.bytes }
    }

    fn from_byte_array(block: &GenericArray<u8, N>) -> Self {
        Block { bytes: *block }
    }
}

impl<N> Default for Block<N>
where
    N: ArrayLength<u8>,
    N: PartialDiv<U8>,
    <N as PartialDiv<U8>>::Output: ArrayLength<u64>,
    N::ArrayType: Copy,
    <<N as PartialDiv<U8>>::Output as ArrayLength<u64>>::ArrayType: Copy,
{
    fn default() -> Self {
        Block {
            words: GenericArray::default(),
        }
    }
}

impl<N> core::ops::BitXor<Block<N>> for Block<N>
where
    N: ArrayLength<u8>,
    N: PartialDiv<U8>,
    <N as PartialDiv<U8>>::Output: ArrayLength<u64>,
    N::ArrayType: Copy,
    <<N as PartialDiv<U8>>::Output as ArrayLength<u64>>::ArrayType: Copy,
{
    type Output = Block<N>;
    fn bitxor(mut self, rhs: Block<N>) -> Self::Output {
        // XOR is endian-agnostic
        for (s, r) in unsafe { &mut self.words }
            .iter_mut()
            .zip(unsafe { &rhs.words })
        {
            *s ^= *r;
        }
        self
    }
}

#[derive(Clone)]
struct State<X> {
    t: (u64, u64),
    x: X,
}

impl<X> State<X> {
    fn new(t1: u64, x: X) -> Self {
        let t = (0, t1);
        State { t, x }
    }
}

impl<X> core::fmt::Debug for State<X> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("State<X>")
            .field("t", &"(unknown)")
            .field("x", &"(unknown)")
            .finish()
    }
}

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
    ($name:ident, $threefish:ident, $state_bytes:ty, $state_bits:expr) => {
        #[derive(Clone)]
        pub struct $name<N: Unsigned + ArrayLength<u8> + NonZero + Default> {
            state: State<Block<$state_bytes>>,
            buffer: BlockBuffer<$state_bytes, Lazy>,
            _output: core::marker::PhantomData<GenericArray<u8, N>>,
        }

        impl<N> core::fmt::Debug for $name<N>
        where
            N: Unsigned + ArrayLength<u8> + NonZero + Default,
        {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                f.debug_struct("Skein").field("state", &self.state).finish()
            }
        }

        impl<N> $name<N>
        where
            N: Unsigned + ArrayLength<u8> + NonZero + Default,
        {
            fn process_block(
                state: &mut State<Block<$state_bytes>>,
                block: &GenericArray<u8, $state_bytes>,
                byte_count_add: usize,
            ) {
                let block = Block::from_byte_array(block);
                state.t.0 += byte_count_add as u64;
                let mut tweak = [0u8; 16];
                tweak[..8].copy_from_slice(&state.t.0.to_le_bytes());
                tweak[8..].copy_from_slice(&state.t.1.to_le_bytes());
                let mut key = [0u8; { $state_bits / 8 }];
                key[..].copy_from_slice(state.x.as_byte_array());
                let fish = $threefish::new_with_tweak(&key, &tweak);
                let mut x = block.clone();
                fish.encrypt_block(x.as_byte_array_mut());
                state.x = x ^ block;
                state.t.1 &= !T1_FLAG_FIRST;
            }
        }

        impl<N> Default for $name<N>
        where
            N: Unsigned + ArrayLength<u8> + NonZero + Default,
        {
            fn default() -> Self {
                // build and process config block
                let mut state = State::new(
                    T1_FLAG_FIRST | T1_BLK_TYPE_CFG | T1_FLAG_FINAL,
                    Block::default(),
                );
                let mut cfg = GenericArray::<u8, $state_bytes>::default();
                cfg[..8].copy_from_slice(&SCHEMA_VER.to_le_bytes());
                cfg[8..16].copy_from_slice(&(N::to_u64() * 8).to_le_bytes());
                cfg[16..24].copy_from_slice(&CFG_TREE_INFO_SEQUENTIAL.to_le_bytes());
                Self::process_block(&mut state, &cfg, CFG_STR_LEN);

                // The chaining vars ctx->X are now initialized for the given hashBitLen.
                // Set up to process the data message portion of the hash (default)
                state.t = Default::default();
                state.t.1 = T1_FLAG_FIRST | T1_BLK_TYPE_MSG;
                Self {
                    state,
                    buffer: Default::default(),
                    _output: Default::default(),
                }
            }
        }

        impl<N> digest::crypto_common::BlockSizeUser for $name<N>
        where
            N: Unsigned + ArrayLength<u8> + NonZero + Default,
        {
            type BlockSize = <$threefish as digest::crypto_common::BlockSizeUser>::BlockSize;
        }

        impl<N> digest::Update for $name<N>
        where
            N: Unsigned + ArrayLength<u8> + NonZero + Default,
        {
            fn update(&mut self, data: &[u8]) {
                let buffer = &mut self.buffer;
                let state = &mut self.state;
                buffer.digest_blocks(data.as_ref(), |blocks| {
                    for block in blocks {
                        Self::process_block(state, block, $state_bits / 8)
                    }
                });
            }
        }

        impl<N> digest::OutputSizeUser for $name<N>
        where
            N: Unsigned + ArrayLength<u8> + NonZero + Default,
        {
            type OutputSize = N;
        }

        impl<N> digest::FixedOutput for $name<N>
        where
            N: Unsigned + ArrayLength<u8> + NonZero + Default,
        {
            fn finalize_into(mut self, out: &mut digest::Output<Self>) {
                self.state.t.1 |= T1_FLAG_FINAL;
                let pos = self.buffer.get_pos();
                let final_block = self.buffer.pad_with_zeros();
                Self::process_block(&mut self.state, final_block, pos);

                // run Threefish in "counter mode" to generate output
                for (i, chunk) in out.chunks_mut($state_bits / 8).enumerate() {
                    let mut ctr = State::new(
                        T1_FLAG_FIRST | T1_BLK_TYPE_OUT | T1_FLAG_FINAL,
                        self.state.x,
                    );
                    let mut b = GenericArray::<u8, $state_bytes>::default();
                    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    Self::process_block(&mut ctr, &b, 8);
                    let n = chunk.len();
                    chunk.copy_from_slice(&ctr.x.bytes()[..n]);
                }
            }
        }

        impl<N> digest::Reset for $name<N>
        where
            N: Unsigned + ArrayLength<u8> + NonZero + Default,
        {
            fn reset(&mut self) {
                *self = Self::default();
            }
        }
    };
}

#[rustfmt::skip]
define_hasher!(Skein256, Threefish256, U32, 256);
#[rustfmt::skip]
define_hasher!(Skein512, Threefish512, U64, 512);
#[rustfmt::skip]
define_hasher!(Skein1024, Threefish1024, U128, 1024);

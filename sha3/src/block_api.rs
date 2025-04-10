use crate::{DEFAULT_ROUND_COUNT, PLEN, Sha3XofReaderCore, xor_block};
use core::{fmt, marker::PhantomData};
use digest::{
    HashMarker, Output,
    array::ArraySize,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, ExtendableOutputCore,
        FixedOutputCore, OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::{
        BlockSizes,
        hazmat::{DeserializeStateError, SerializableState, SerializedState},
    },
    typenum::{Gr, IsGreater, IsLessOrEqual, LeEq, NonZero, U0, U200},
};

/// Core Sha3 fixed output hasher state.
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct Sha3FixedCore<Rate, OutputSize, const PAD: u8, const ROUNDS: usize = DEFAULT_ROUND_COUNT>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    state: [u64; PLEN],
    _pd: PhantomData<(Rate, OutputSize)>,
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> HashMarker
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> BlockSizeUser
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    type BlockSize = Rate;
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> BufferKindUser
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    type BufferKind = Eager;
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> OutputSizeUser
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    type OutputSize = OutputSize;
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> UpdateCore
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            xor_block(&mut self.state, block);
            keccak::p1600(&mut self.state, ROUNDS);
        }
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> FixedOutputCore
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200> + IsGreater<U0>,
    LeEq<Rate, U200>: NonZero,
    Gr<OutputSize, U0>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = PAD;
        let n = block.len();
        block[n - 1] |= 0x80;

        xor_block(&mut self.state, &block);
        keccak::p1600(&mut self.state, ROUNDS);

        for (o, s) in out.chunks_mut(8).zip(self.state.iter()) {
            o.copy_from_slice(&s.to_le_bytes()[..o.len()]);
        }
    }
}

impl<Rate, const PAD: u8, const ROUNDS: usize> ExtendableOutputCore
    for Sha3FixedCore<Rate, U0, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
{
    type ReaderCore = Sha3XofReaderCore<Rate, ROUNDS>;

    #[inline]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = PAD;
        let n = block.len();
        block[n - 1] |= 0x80;

        xor_block(&mut self.state, &block);
        keccak::p1600(&mut self.state, ROUNDS);

        Sha3XofReaderCore::new(&self.state)
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> Default
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    #[inline]
    fn default() -> Self {
        Self {
            state: Default::default(),
            _pd: PhantomData,
        }
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> Reset
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> AlgorithmName
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha3") // TODO
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> fmt::Debug
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS> { ... }")
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> Drop
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> digest::zeroize::ZeroizeOnDrop
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> SerializableState
    for Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    OutputSize: ArraySize + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
    LeEq<OutputSize, U200>: NonZero,
{
    type SerializedStateSize = U200;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();
        let chunks = serialized_state.chunks_exact_mut(8);
        for (val, chunk) in self.state.iter().zip(chunks) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let mut state = [0; PLEN];
        let chunks = serialized_state.chunks_exact(8);
        for (val, chunk) in state.iter_mut().zip(chunks) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        Ok(Self {
            state,
            _pd: PhantomData,
        })
    }
}

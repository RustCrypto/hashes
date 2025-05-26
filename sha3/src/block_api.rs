use crate::{DEFAULT_ROUND_COUNT, PLEN};
use core::{fmt, marker::PhantomData};
use digest::{
    HashMarker, Output,
    array::ArraySize,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, ExtendableOutputCore,
        FixedOutputCore, OutputSizeUser, Reset, UpdateCore, XofReaderCore,
    },
    crypto_common::{
        BlockSizes,
        hazmat::{DeserializeStateError, SerializableState, SerializedState},
    },
    typenum::{IsLessOrEqual, True, U0, U200},
};

pub use crate::cshake::{CShake128Core, CShake256Core};

/// Core Sha3 fixed output hasher state.
#[derive(Clone)]
pub struct Sha3HasherCore<
    Rate,
    OutputSize,
    const PAD: u8,
    const ROUNDS: usize = DEFAULT_ROUND_COUNT,
> where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    state: [u64; PLEN],
    _pd: PhantomData<(Rate, OutputSize)>,
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> HashMarker
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> BlockSizeUser
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    type BlockSize = Rate;
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> BufferKindUser
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    type BufferKind = Eager;
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> OutputSizeUser
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    type OutputSize = OutputSize;
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> UpdateCore
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
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
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
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
    for Sha3HasherCore<Rate, U0, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    type ReaderCore = Sha3ReaderCore<Rate, ROUNDS>;

    #[inline]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = PAD;
        let n = block.len();
        block[n - 1] |= 0x80;

        xor_block(&mut self.state, &block);
        keccak::p1600(&mut self.state, ROUNDS);

        Sha3ReaderCore::new(&self.state)
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> Default
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
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
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> AlgorithmName
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha3") // TODO
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> fmt::Debug
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS> { ... }")
    }
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> Drop
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
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
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
}

impl<Rate, OutputSize, const PAD: u8, const ROUNDS: usize> SerializableState
    for Sha3HasherCore<Rate, OutputSize, PAD, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
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

/// Core Sha3 XOF reader.
#[derive(Clone)]
pub struct Sha3ReaderCore<Rate, const ROUNDS: usize = DEFAULT_ROUND_COUNT>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    state: [u64; PLEN],
    _pd: PhantomData<Rate>,
}

impl<Rate, const ROUNDS: usize> Sha3ReaderCore<Rate, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    pub(crate) fn new(state: &[u64; PLEN]) -> Self {
        Self {
            state: *state,
            _pd: PhantomData,
        }
    }
}

impl<Rate, const ROUNDS: usize> BlockSizeUser for Sha3ReaderCore<Rate, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    type BlockSize = Rate;
}

impl<Rate, const ROUNDS: usize> XofReaderCore for Sha3ReaderCore<Rate, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    #[inline]
    fn read_block(&mut self) -> Block<Self> {
        let mut block = Block::<Self>::default();
        for (src, dst) in self.state.iter().zip(block.chunks_mut(8)) {
            dst.copy_from_slice(&src.to_le_bytes()[..dst.len()]);
        }
        keccak::p1600(&mut self.state, ROUNDS);
        block
    }
}

impl<Rate, const ROUNDS: usize> Drop for Sha3ReaderCore<Rate, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

impl<Rate, const ROUNDS: usize> fmt::Debug for Sha3ReaderCore<Rate, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha3ReaderCore { ... }")
    }
}

#[cfg(feature = "zeroize")]
impl<Rate, const ROUNDS: usize> digest::zeroize::ZeroizeOnDrop for Sha3ReaderCore<Rate, ROUNDS> where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>
{
}

pub(crate) fn xor_block(state: &mut [u64; PLEN], block: &[u8]) {
    assert!(block.len() < 8 * PLEN);

    let mut chunks = block.chunks_exact(8);
    for (s, chunk) in state.iter_mut().zip(&mut chunks) {
        *s ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }

    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut buf = [0u8; 8];
        buf[..rem.len()].copy_from_slice(rem);
        let n = block.len() / 8;
        state[n] ^= u64::from_le_bytes(buf);
    }
}

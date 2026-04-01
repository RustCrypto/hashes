use core::{fmt, marker::PhantomData};
use digest::{
    HashMarker, Output,
    array::ArraySize,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, ExtendableOutputCore,
        FixedOutputCore, OutputSizeUser, Reset, UpdateCore, XofReaderCore,
    },
    block_buffer::BlockSizes,
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{IsLessOrEqual, True, U0, U200},
};
use keccak::{Keccak, State1600};

/// Core SHA-3 hasher state.
#[derive(Clone)]
pub struct Sha3HasherCore<Rate, OutputSize, const PAD: u8>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    state: State1600,
    keccak: Keccak,
    _pd: PhantomData<(Rate, OutputSize)>,
}

impl<Rate, OutputSize, const PAD: u8> HashMarker for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
}

impl<Rate, OutputSize, const PAD: u8> BlockSizeUser for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    type BlockSize = Rate;
}

impl<Rate, OutputSize, const PAD: u8> BufferKindUser for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    type BufferKind = Eager;
}

impl<Rate, OutputSize, const PAD: u8> OutputSizeUser for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    type OutputSize = OutputSize;
}

impl<Rate, OutputSize, const PAD: u8> UpdateCore for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.keccak.with_f1600(|f1600| {
            for block in blocks {
                xor_block(&mut self.state, block);
                f1600(&mut self.state);
            }
        });
    }
}

impl<Rate, OutputSize, const PAD: u8> FixedOutputCore for Sha3HasherCore<Rate, OutputSize, PAD>
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

        self.keccak.with_f1600(|f1600| {
            xor_block(&mut self.state, &block);
            f1600(&mut self.state);

            for (o, s) in out.chunks_mut(8).zip(self.state.as_mut().iter()) {
                o.copy_from_slice(&s.to_le_bytes()[..o.len()]);
            }
        });
    }
}

impl<Rate, const PAD: u8> ExtendableOutputCore for Sha3HasherCore<Rate, U0, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    type ReaderCore = Sha3ReaderCore<Rate>;

    #[inline]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = PAD;
        let n = block.len();
        block[n - 1] |= 0x80;

        self.keccak.with_f1600(|f1600| {
            xor_block(&mut self.state, &block);
            f1600(&mut self.state);
        });

        Sha3ReaderCore::new(&self.state, self.keccak)
    }
}

impl<Rate, OutputSize, const PAD: u8> Default for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    #[inline]
    fn default() -> Self {
        Self {
            state: Default::default(),
            keccak: Keccak::new(),
            _pd: PhantomData,
        }
    }
}

impl<Rate, OutputSize, const PAD: u8> Reset for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<Rate, OutputSize, const PAD: u8> AlgorithmName for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: change algorithm name depending on the generic parameters
        f.write_str("Sha3")
    }
}

impl<Rate, OutputSize, const PAD: u8> fmt::Debug for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha3FixedCore<Rate, OutputSize, PAD, ROUNDS> { ... }")
    }
}

impl<Rate, OutputSize, const PAD: u8> Drop for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.as_mut().zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate, OutputSize, const PAD: u8> digest::zeroize::ZeroizeOnDrop
    for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
}

impl<Rate, OutputSize, const PAD: u8> SerializableState for Sha3HasherCore<Rate, OutputSize, PAD>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
    OutputSize: ArraySize + IsLessOrEqual<U200, Output = True>,
{
    type SerializedStateSize = U200;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();
        let chunks = serialized_state.chunks_exact_mut(8);
        for (val, chunk) in self.state.as_ref().iter().zip(chunks) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let mut state = State1600::default();
        let chunks = serialized_state.chunks_exact(8);
        for (val, chunk) in state.iter_mut().zip(chunks) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        Ok(Self {
            state,
            keccak: Keccak::new(),
            _pd: PhantomData,
        })
    }
}

/// Core SHA-3 XOF reader.
#[derive(Clone)]
pub struct Sha3ReaderCore<Rate>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    state: State1600,
    keccak: Keccak,
    _pd: PhantomData<Rate>,
}

impl<Rate> Sha3ReaderCore<Rate>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    pub(crate) fn new(&state: &State1600, keccak: Keccak) -> Self {
        let _pd = PhantomData;
        Self { state, keccak, _pd }
    }
}

impl<Rate> BlockSizeUser for Sha3ReaderCore<Rate>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    type BlockSize = Rate;
}

impl<Rate> XofReaderCore for Sha3ReaderCore<Rate>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    #[inline]
    fn read_block(&mut self) -> Block<Self> {
        let mut block = Block::<Self>::default();
        for (src, dst) in self.state.iter().zip(block.chunks_mut(8)) {
            dst.copy_from_slice(&src.to_le_bytes()[..dst.len()]);
        }
        self.keccak.with_f1600(|f1600| f1600(&mut self.state));
        block
    }
}

impl<Rate> Drop for Sha3ReaderCore<Rate>
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

impl<Rate> fmt::Debug for Sha3ReaderCore<Rate>
where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha3ReaderCore { ... }")
    }
}

#[cfg(feature = "zeroize")]
impl<Rate> digest::zeroize::ZeroizeOnDrop for Sha3ReaderCore<Rate> where
    Rate: BlockSizes + IsLessOrEqual<U200, Output = True>
{
}

pub(crate) fn xor_block(state: &mut State1600, block: &[u8]) {
    assert!(size_of_val(block) < size_of_val(state));

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

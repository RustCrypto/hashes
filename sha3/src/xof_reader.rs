use crate::{DEFAULT_ROUND_COUNT, PLEN};
use core::{fmt, marker::PhantomData};
use digest::{
    block_api::{Block, BlockSizeUser, XofReaderCore},
    crypto_common::BlockSizes,
    typenum::{IsLessOrEqual, True, U200},
};

/// Core Sha3 XOF reader.
#[derive(Clone)]
#[allow(non_camel_case_types)]
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

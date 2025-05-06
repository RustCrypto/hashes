use crate::{DEFAULT_ROUND_COUNT, PLEN};
use core::marker::PhantomData;
use digest::{
    core_api::{Block, BlockSizeUser, XofReaderCore},
    crypto_common::BlockSizes,
    typenum::{IsLessOrEqual, LeEq, NonZero, U200},
};

/// Core Sha3 XOF reader.
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct Sha3ReaderCore<Rate, const ROUNDS: usize = DEFAULT_ROUND_COUNT>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
{
    state: [u64; PLEN],
    _pd: PhantomData<Rate>,
}

impl<Rate, const ROUNDS: usize> Sha3ReaderCore<Rate, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
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
    Rate: BlockSizes + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
{
    type BlockSize = Rate;
}

impl<Rate, const ROUNDS: usize> XofReaderCore for Sha3ReaderCore<Rate, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
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
    Rate: BlockSizes + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
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
impl<Rate, const ROUNDS: usize> digest::zeroize::ZeroizeOnDrop for Sha3ReaderCore<Rate, ROUNDS>
where
    Rate: BlockSizes + IsLessOrEqual<U200>,
    LeEq<Rate, U200>: NonZero,
{
}

use digest::{
    block_api::Eager,
    block_buffer::{BlockBuffer, BlockSizes},
};
use keccak::{Fn1600, State1600};

use crate::{consts::PAD, utils::xor_block};

#[derive(Default, Clone)]
pub(crate) struct TurboShake<Rate: BlockSizes> {
    state: State1600,
    buffer: BlockBuffer<Rate, Eager>,
}

impl<Rate: BlockSizes> TurboShake<Rate> {
    pub(crate) fn absorb(&mut self, p1600: Fn1600, data: &[u8]) {
        let Self { state, buffer } = self;
        buffer.digest_blocks(data, |blocks| {
            for block in blocks {
                xor_block(state, block);
                p1600(state)
            }
        })
    }

    pub(crate) fn finalize<const DS: u8>(&mut self, p1600: Fn1600) {
        let Self { state, buffer } = self;
        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = DS;
        let n = block.len();
        block[n - 1] |= PAD;
        xor_block(state, &block);
        p1600(state);
    }

    pub(crate) fn full_node_finalize(&mut self, p1600: Fn1600, cv_dst: &mut [u8]) {
        let tail_data = self.buffer.get_data();
        crate::node_turbo_shake::finalize::<Rate>(p1600, &mut self.state, tail_data, cv_dst);
    }

    pub(crate) fn state(&self) -> &State1600 {
        &self.state
    }

    pub(crate) fn reset(&mut self) {
        self.state = Default::default();
        self.buffer.reset();
    }
}

impl<Rate: BlockSizes> Drop for TurboShake<Rate> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            // `buffer` is zeroized by `Drop`
        }
    }
}

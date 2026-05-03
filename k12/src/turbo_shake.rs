use crate::consts::INTERMEDIATE_NODE_DS;
use digest::array::ArraySize;
use keccak::{Fn1600, State1600};
use sponge_cursor::SpongeCursor;

use crate::utils::copy_cv;

#[derive(Default, Clone)]
pub(crate) struct TurboShake<Rate: ArraySize> {
    state: State1600,
    cursor: SpongeCursor<Rate>,
}

impl<Rate: ArraySize> TurboShake<Rate> {
    pub(crate) fn absorb(&mut self, p1600: Fn1600, data: &[u8]) {
        self.cursor.absorb_u64_le(&mut self.state, p1600, data);
    }

    pub(crate) fn pad<const DS: u8>(&mut self) {
        let pos = self.cursor.pos();
        let word_offset = pos / 8;
        let byte_offset = pos % 8;

        let pad = u64::from(DS) << (8 * byte_offset);
        self.state[word_offset] ^= pad;
        self.state[Rate::USIZE / 8 - 1] ^= 1 << 63;
    }

    pub(crate) fn finalize_node(&mut self, p1600: Fn1600, cv_dst: &mut [u8]) {
        self.pad::<INTERMEDIATE_NODE_DS>();
        p1600(&mut self.state);
        copy_cv(self.state(), cv_dst);
    }

    pub(crate) fn state(&self) -> &State1600 {
        &self.state
    }

    pub(crate) fn reset(&mut self) {
        self.state = Default::default();
        self.cursor = Default::default();
    }
}

impl<Rate: ArraySize> Drop for TurboShake<Rate> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.cursor.zeroize();
        }
    }
}

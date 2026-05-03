use crate::consts::ROUNDS;
use core::fmt;
use digest::{XofReader, array::ArraySize};
use keccak::{Keccak, State1600};
use sponge_cursor::SpongeCursor;

/// KangarooTwelve XOF reader generic over rate.
#[derive(Clone)]
pub struct KtReader<Rate: ArraySize> {
    state: State1600,
    cursor: SpongeCursor<Rate>,
    keccak: Keccak,
}

impl<Rate: ArraySize> KtReader<Rate> {
    pub(crate) fn new(state: &State1600, keccak: Keccak) -> Self {
        Self {
            state: *state,
            cursor: Default::default(),
            keccak,
        }
    }
}

impl<Rate: ArraySize> XofReader for KtReader<Rate> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        self.keccak.with_p1600::<ROUNDS>(|p1600| {
            self.cursor.squeeze_u64_le(&mut self.state, p1600, buf);
        });
    }
}

impl<Rate: ArraySize> fmt::Debug for KtReader<Rate> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match Rate::USIZE {
            168 => "Kt128Reader { ... }",
            136 => "Kt256Reader { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<Rate: ArraySize> Drop for KtReader<Rate> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            // self.buffer is zeroized by its `Drop`
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate: ArraySize> digest::zeroize::ZeroizeOnDrop for KtReader<Rate> {}

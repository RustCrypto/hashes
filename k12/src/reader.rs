use crate::consts::ROUNDS;
use core::fmt;
use digest::XofReader;
use keccak::{Keccak, State1600};
use sponge_cursor::SpongeCursor;

/// KangarooTwelve XOF reader generic over rate.
#[derive(Clone)]
pub struct KtReader<const RATE: usize> {
    state: State1600,
    cursor: SpongeCursor<RATE>,
    keccak: Keccak,
}

impl<const RATE: usize> KtReader<RATE> {
    pub(crate) fn new(state: &State1600, keccak: Keccak) -> Self {
        Self {
            state: *state,
            cursor: Default::default(),
            keccak,
        }
    }
}

impl<const RATE: usize> XofReader for KtReader<RATE> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        self.keccak.with_p1600::<ROUNDS>(|p1600| {
            self.cursor.squeeze_read_u64_le(&mut self.state, p1600, buf);
        });
    }
}

impl<const RATE: usize> fmt::Debug for KtReader<RATE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match RATE {
            168 => "Kt128Reader { ... }",
            136 => "Kt256Reader { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<const RATE: usize> Drop for KtReader<RATE> {
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
impl<const RATE: usize> digest::zeroize::ZeroizeOnDrop for KtReader<RATE> {}

use ascon::State;
use digest::XofReader;
use sponge_cursor::SpongeCursor;

/// XOF reader used by Ascon-XOF128 and Ascon-CXOF128
#[derive(Clone, Debug)]
pub struct AsconXof128Reader {
    state: State,
    cursor: SpongeCursor<8>,
}

impl AsconXof128Reader {
    pub(super) fn new(state: &State) -> Self {
        Self {
            state: *state,
            cursor: Default::default(),
        }
    }
}

impl XofReader for AsconXof128Reader {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        self.cursor
            .squeeze_read_u64_le(&mut self.state, ascon::permute12, buf);
    }
}

impl Drop for AsconXof128Reader {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.cursor.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for AsconXof128Reader {}

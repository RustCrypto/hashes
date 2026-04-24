use ascon::State;
use digest::{XofReader, block_buffer::ReadBuffer, consts::U8};

/// XOF reader used by Ascon-XOF128 and Ascon-CXOF128
#[derive(Clone, Debug)]
pub struct AsconXof128Reader {
    state: State,
    buffer: ReadBuffer<U8>,
}

impl AsconXof128Reader {
    pub(super) fn new(state: &State) -> Self {
        Self {
            state: *state,
            buffer: Default::default(),
        }
    }
}

impl XofReader for AsconXof128Reader {
    fn read(&mut self, buf: &mut [u8]) {
        self.buffer.read(buf, |dst| {
            ascon::permute12(&mut self.state);
            *dst = self.state[0].to_le_bytes().into();
        });
    }
}

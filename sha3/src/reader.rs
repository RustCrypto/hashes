use crate::state::Sha3State;
use digest::XofReader;
#[cfg(feature = "std")]
use std::io;

/// Reader state for extracting extendable output.
pub struct Sha3XofReader {
    state: Sha3State,
    rate: usize,
    pos: usize,
}

impl Sha3XofReader {
    pub(crate) fn new(state: Sha3State, rate: usize) -> Self {
        Sha3XofReader {
            state,
            rate,
            pos: 0,
        }
    }
}

impl XofReader for Sha3XofReader {
    fn read(&mut self, mut buffer: &mut [u8]) {
        let rem = self.rate - self.pos;
        let n = buffer.len();
        if n >= rem {
            let (l, r) = { buffer }.split_at_mut(rem);
            buffer = r;
            self.state.as_bytes(|state| {
                l.copy_from_slice(&state[self.pos..self.rate]);
            });
            self.state.apply_f();
        } else {
            self.state.as_bytes(|state| {
                buffer.copy_from_slice(&state[self.pos..self.pos + n]);
            });
            self.pos += n;
            return;
        }

        while buffer.len() >= self.rate {
            let (l, r) = { buffer }.split_at_mut(self.rate);
            buffer = r;

            self.state.as_bytes(|state| {
                l.copy_from_slice(&state[..self.rate]);
            });
            self.state.apply_f();
        }

        let n = buffer.len();
        self.pos = n;
        self.state.as_bytes(|state| {
            buffer.copy_from_slice(&state[..n]);
        });
    }
}

#[cfg(feature = "std")]
impl io::Read for Sha3XofReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        <Self as XofReader>::read(self, buf);
        Ok(buf.len())
    }
}

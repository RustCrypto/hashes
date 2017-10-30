use digest;
use byte_tools::write_u64v_le;
use consts::PLEN;
use core::mem::transmute;
use core::cmp::min;
use keccak;

/// Reader state for extracting extendable output.
pub struct Sha3XofReader {
    state: [u64; PLEN],
    rate: usize,
}

impl Sha3XofReader {
    pub(crate) fn new(state: [u64; PLEN], rate: usize) -> Self {
        Sha3XofReader{ state: state, rate: rate }
    }
}

impl digest::XofReader for Sha3XofReader {
    fn read(&mut self, buffer: &mut [u8]) {
       let mut offset = 0;

        let buffer_len = buffer.len();

        let in_len = buffer.len();
        let mut in_pos: usize = 0;

        // Squeeze
        while in_pos < in_len {
            let rate = self.rate;
            let off_n = offset % rate;
            let mut nread = min(rate - off_n, in_len - in_pos);
            if buffer_len != 0 {
                nread = min(nread, buffer_len - offset);
            }


            let mut state_copy;
            let state_ref: &[u8; PLEN*8] = if cfg!(target_endian = "little") {
                unsafe { transmute(&mut self.state) }
            } else if cfg!(target_endian = "big") {
                state_copy = [0u8; PLEN*8];
                write_u64v_le(&mut state_copy, &self.state);
                &state_copy
            } else { unreachable!() };


            let off = offset % self.rate;
            let part = &state_ref[off..off+nread];
            buffer[in_pos..in_pos+nread].copy_from_slice(part);

            in_pos += nread;

            if off_n + nread != rate {
                offset += nread;
                break;
            }

            if buffer_len == 0 {
                offset = 0;
            } else {
                offset += nread;
            }

            keccak::f(&mut self.state);
        }

        assert!(buffer_len != 0 && buffer_len == offset, "Not everything squeezed");
    }
}
use keccak;
use byte_tools::{read_u64v_le, write_u64v_le};
#[cfg(feature = "std")]
use std::mem;
#[cfg(not(feature = "std"))]
use core::mem;

const PLEN: usize = 25;

#[derive(Clone, Default)]
pub(crate) struct Sha3State {
    pub state: [u64; PLEN],
}

impl Sha3State {
    #[inline(always)]
    pub(crate) fn absorb_block(&mut self, block: &[u8]) {
        assert_eq!(block.len() % 8, 0);
        let n = block.len()/8;

        let mut buf;
        let buf: &[u64] = if cfg!(target_endian = "little") {
            unsafe { mem::transmute(block) }
        } else if cfg!(target_endian = "big") {
            buf = [0u64; 21];
            let buf = &mut buf[..n];
            read_u64v_le(buf, block);
            buf
        } else { unreachable!() };

        for (d, i) in self.state[..n].iter_mut().zip(buf) {
            *d ^= *i;
        }

        keccak::f1600(&mut self.state);
    }

    #[inline(always)]
    pub(crate) fn as_bytes<F: FnOnce(&[u8; 8*PLEN])>(&self, f: F) {
        let mut data_copy;
        let data_ref: &[u8; 8*PLEN] = if cfg!(target_endian = "little") {
            unsafe { mem::transmute(&self.state) }
        } else {
            data_copy = [0u8; 8*PLEN];
            write_u64v_le(&mut data_copy, &self.state);
            &data_copy
        };
        f(data_ref);
    }

    #[inline(always)]
    pub(crate) fn apply_f(&mut self) {
        keccak::f1600(&mut self.state);
    }
}
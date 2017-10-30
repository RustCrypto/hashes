use keccak;
use consts::PLEN;
use byte_tools::read_u64v_le;
use core::mem::transmute;

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
            unsafe { transmute(block) }
        } else if cfg!(target_endian = "big") {
            buf = [0u64; 21];
            let buf = &mut buf[..n];
            read_u64v_le(buf, block);
            buf
        } else { unreachable!() };

        for (d, i) in self.state[..n].iter_mut().zip(buf) {
            *d ^= *i;
        }

        keccak::f(&mut self.state);
    }
}
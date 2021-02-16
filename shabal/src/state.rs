use core::{convert::TryInto, mem};
use digest::{consts::U64, generic_array::GenericArray};

pub(crate) type BlockSize = U64;
pub(crate) type Block = GenericArray<u8, BlockSize>;

/// Inner state of Shabal hash functions.
#[derive(Clone)]
pub(crate) struct EngineState {
    a: [u32; 12],
    b: [u32; 16],
    c: [u32; 16],
    whigh: u32,
    wlow: u32,
}

impl EngineState {
    pub(crate) const fn new((a, b, c): ([u32; 12], [u32; 16], [u32; 16])) -> Self {
        let (wlow, whigh) = (1, 0);
        Self {
            a,
            b,
            c,
            wlow,
            whigh,
        }
    }

    pub(crate) fn get_b(&self) -> &[u32; 16] {
        &self.b
    }

    fn add_m(&mut self, m: &[u32; 16]) {
        for (b, m) in self.b.iter_mut().zip(m) {
            *b = b.wrapping_add(*m);
        }
    }

    fn sub_m(&mut self, m: &[u32; 16]) {
        for (c, m) in self.c.iter_mut().zip(m) {
            *c = c.wrapping_sub(*m);
        }
    }

    fn inc_w(&mut self) {
        self.wlow = self.wlow.wrapping_add(1);
        if self.wlow == 0 {
            self.whigh = self.whigh.wrapping_add(1);
        }
    }

    fn xor_w(&mut self) {
        self.a[0] ^= self.wlow;
        self.a[1] ^= self.whigh;
    }

    fn perm(&mut self, m: &[u32; 16]) {
        for b in self.b.iter_mut() {
            *b = b.wrapping_shl(17) | b.wrapping_shr(15);
        }
        self.perm_blocks(m);

        let a = &mut self.a;
        let c = &self.c;
        a[0] = a[0]
            .wrapping_add(c[11])
            .wrapping_add(c[15])
            .wrapping_add(c[3]);
        a[1] = a[1]
            .wrapping_add(c[12])
            .wrapping_add(c[0])
            .wrapping_add(c[4]);
        a[2] = a[2]
            .wrapping_add(c[13])
            .wrapping_add(c[1])
            .wrapping_add(c[5]);
        a[3] = a[3]
            .wrapping_add(c[14])
            .wrapping_add(c[2])
            .wrapping_add(c[6]);
        a[4] = a[4]
            .wrapping_add(c[15])
            .wrapping_add(c[3])
            .wrapping_add(c[7]);
        a[5] = a[5]
            .wrapping_add(c[0])
            .wrapping_add(c[4])
            .wrapping_add(c[8]);
        a[6] = a[6]
            .wrapping_add(c[1])
            .wrapping_add(c[5])
            .wrapping_add(c[9]);
        a[7] = a[7]
            .wrapping_add(c[2])
            .wrapping_add(c[6])
            .wrapping_add(c[10]);
        a[8] = a[8]
            .wrapping_add(c[3])
            .wrapping_add(c[7])
            .wrapping_add(c[11]);
        a[9] = a[9]
            .wrapping_add(c[4])
            .wrapping_add(c[8])
            .wrapping_add(c[12]);
        a[10] = a[10]
            .wrapping_add(c[5])
            .wrapping_add(c[9])
            .wrapping_add(c[13]);
        a[11] = a[11]
            .wrapping_add(c[6])
            .wrapping_add(c[10])
            .wrapping_add(c[14]);
    }

    #[allow(clippy::too_many_arguments)]
    fn perm_elt(
        &mut self,
        xa0: usize,
        xa1: usize,
        xb0: usize,
        xb1: usize,
        xb2: usize,
        xb3: usize,
        xc0: usize,
        xm: u32,
    ) {
        let a = &mut self.a;
        let b = &mut self.b;
        let xc = self.c[xc0];

        a[xa0] = (a[xa0]
            ^ ((a[xa1].wrapping_shl(15u32) | a[xa1].wrapping_shr(17u32)).wrapping_mul(5u32))
            ^ xc)
            .wrapping_mul(3u32)
            ^ b[xb1]
            ^ (b[xb2] & !b[xb3])
            ^ xm;
        b[xb0] = !((b[xb0].wrapping_shl(1) | b[xb0].wrapping_shr(31)) ^ a[xa0]);
    }

    fn perm_blocks(&mut self, m: &[u32; 16]) {
        self.perm_elt(0, 11, 0, 13, 9, 6, 8, m[0]);
        self.perm_elt(1, 0, 1, 14, 10, 7, 7, m[1]);
        self.perm_elt(2, 1, 2, 15, 11, 8, 6, m[2]);
        self.perm_elt(3, 2, 3, 0, 12, 9, 5, m[3]);
        self.perm_elt(4, 3, 4, 1, 13, 10, 4, m[4]);
        self.perm_elt(5, 4, 5, 2, 14, 11, 3, m[5]);
        self.perm_elt(6, 5, 6, 3, 15, 12, 2, m[6]);
        self.perm_elt(7, 6, 7, 4, 0, 13, 1, m[7]);
        self.perm_elt(8, 7, 8, 5, 1, 14, 0, m[8]);
        self.perm_elt(9, 8, 9, 6, 2, 15, 15, m[9]);
        self.perm_elt(10, 9, 10, 7, 3, 0, 14, m[10]);
        self.perm_elt(11, 10, 11, 8, 4, 1, 13, m[11]);
        self.perm_elt(0, 11, 12, 9, 5, 2, 12, m[12]);
        self.perm_elt(1, 0, 13, 10, 6, 3, 11, m[13]);
        self.perm_elt(2, 1, 14, 11, 7, 4, 10, m[14]);
        self.perm_elt(3, 2, 15, 12, 8, 5, 9, m[15]);
        self.perm_elt(4, 3, 0, 13, 9, 6, 8, m[0]);
        self.perm_elt(5, 4, 1, 14, 10, 7, 7, m[1]);
        self.perm_elt(6, 5, 2, 15, 11, 8, 6, m[2]);
        self.perm_elt(7, 6, 3, 0, 12, 9, 5, m[3]);
        self.perm_elt(8, 7, 4, 1, 13, 10, 4, m[4]);
        self.perm_elt(9, 8, 5, 2, 14, 11, 3, m[5]);
        self.perm_elt(10, 9, 6, 3, 15, 12, 2, m[6]);
        self.perm_elt(11, 10, 7, 4, 0, 13, 1, m[7]);
        self.perm_elt(0, 11, 8, 5, 1, 14, 0, m[8]);
        self.perm_elt(1, 0, 9, 6, 2, 15, 15, m[9]);
        self.perm_elt(2, 1, 10, 7, 3, 0, 14, m[10]);
        self.perm_elt(3, 2, 11, 8, 4, 1, 13, m[11]);
        self.perm_elt(4, 3, 12, 9, 5, 2, 12, m[12]);
        self.perm_elt(5, 4, 13, 10, 6, 3, 11, m[13]);
        self.perm_elt(6, 5, 14, 11, 7, 4, 10, m[14]);
        self.perm_elt(7, 6, 15, 12, 8, 5, 9, m[15]);
        self.perm_elt(8, 7, 0, 13, 9, 6, 8, m[0]);
        self.perm_elt(9, 8, 1, 14, 10, 7, 7, m[1]);
        self.perm_elt(10, 9, 2, 15, 11, 8, 6, m[2]);
        self.perm_elt(11, 10, 3, 0, 12, 9, 5, m[3]);
        self.perm_elt(0, 11, 4, 1, 13, 10, 4, m[4]);
        self.perm_elt(1, 0, 5, 2, 14, 11, 3, m[5]);
        self.perm_elt(2, 1, 6, 3, 15, 12, 2, m[6]);
        self.perm_elt(3, 2, 7, 4, 0, 13, 1, m[7]);
        self.perm_elt(4, 3, 8, 5, 1, 14, 0, m[8]);
        self.perm_elt(5, 4, 9, 6, 2, 15, 15, m[9]);
        self.perm_elt(6, 5, 10, 7, 3, 0, 14, m[10]);
        self.perm_elt(7, 6, 11, 8, 4, 1, 13, m[11]);
        self.perm_elt(8, 7, 12, 9, 5, 2, 12, m[12]);
        self.perm_elt(9, 8, 13, 10, 6, 3, 11, m[13]);
        self.perm_elt(10, 9, 14, 11, 7, 4, 10, m[14]);
        self.perm_elt(11, 10, 15, 12, 8, 5, 9, m[15]);
    }

    fn swap_b_c(&mut self) {
        mem::swap(&mut self.b, &mut self.c);
    }
}

#[inline]
fn read_m(input: &Block) -> [u32; 16] {
    let mut m = [0u32; 16];
    for (o, chunk) in m.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    m
}

pub(crate) fn compress(state: &mut EngineState, input: &Block) {
    let m = read_m(input);
    state.add_m(&m);
    state.xor_w();
    state.perm(&m);
    state.sub_m(&m);
    state.swap_b_c();
    state.inc_w();
}

pub(crate) fn compress_final(state: &mut EngineState, input: &Block) {
    let m = read_m(input);
    state.add_m(&m);
    state.xor_w();
    state.perm(&m);
    for _ in 0..3 {
        state.swap_b_c();
        state.xor_w();
        state.perm(&m);
    }
}

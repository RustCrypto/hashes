use crate::consts;
use core::{convert::TryInto, fmt, mem, num::Wrapping};
use digest::{
    block_buffer::Eager,
    consts::U64,
    core_api::{
        AlgorithmName, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser, TruncSide,
        UpdateCore, VariableOutputCore,
    },
    generic_array::GenericArray,
    HashMarker, InvalidOutputSize, Output,
};

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;
type M = [Wrapping<u32>; 16];

/// Inner state of Shabal hash functions.
#[derive(Clone)]
pub struct ShabalVarCore {
    a: [Wrapping<u32>; 12],
    b: M,
    c: M,
    w: Wrapping<u64>,
}

impl ShabalVarCore {
    #[allow(clippy::needless_range_loop)]
    fn add_m(&mut self, m: &M) {
        for i in 0..16 {
            self.b[i] += m[i];
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn sub_m(&mut self, m: &M) {
        for i in 0..16 {
            self.c[i] -= m[i];
        }
    }

    fn xor_w(&mut self) {
        self.a[0].0 ^= self.w.0 as u32;
        self.a[1].0 ^= (self.w.0 >> 32) as u32;
    }

    fn perm(&mut self, m: &M) {
        self.b.iter_mut().for_each(|b| b.0 = b.0.rotate_left(17));
        self.perm_blocks(m);

        let a = &mut self.a;
        let c = &self.c;
        a[0] += c[11] + c[15] + c[3];
        a[1] += c[12] + c[0] + c[4];
        a[2] += c[13] + c[1] + c[5];
        a[3] += c[14] + c[2] + c[6];
        a[4] += c[15] + c[3] + c[7];
        a[5] += c[0] + c[4] + c[8];
        a[6] += c[1] + c[5] + c[9];
        a[7] += c[2] + c[6] + c[10];
        a[8] += c[3] + c[7] + c[11];
        a[9] += c[4] + c[8] + c[12];
        a[10] += c[5] + c[9] + c[13];
        a[11] += c[6] + c[10] + c[14];
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
        xm: Wrapping<u32>,
    ) {
        let a = &mut self.a;
        let b = &mut self.b;
        let xc = self.c[xc0];

        let t1 = Wrapping(a[xa1].0.rotate_left(15));
        let t2 = t1 * Wrapping(5);
        let t3 = (a[xa0] ^ t2 ^ xc) * Wrapping(3);
        a[xa0] = t3 ^ b[xb1] ^ (b[xb2] & !b[xb3]) ^ xm;

        let t = Wrapping(b[xb0].0.rotate_left(1));
        b[xb0] = !(t ^ a[xa0]);
    }

    fn perm_blocks(&mut self, m: &M) {
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
fn read_m(input: &Block) -> M {
    let mut m = [Wrapping(0); 16];
    for (o, chunk) in m.iter_mut().zip(input.chunks_exact(4)) {
        let a = chunk.try_into().unwrap();
        *o = Wrapping(u32::from_le_bytes(a));
    }
    m
}

impl HashMarker for ShabalVarCore {}

impl BlockSizeUser for ShabalVarCore {
    type BlockSize = BlockSize;
}

impl BufferKindUser for ShabalVarCore {
    type BufferKind = Eager;
}

impl UpdateCore for ShabalVarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block]) {
        for block in blocks {
            let m = read_m(block);
            self.add_m(&m);
            self.xor_w();
            self.perm(&m);
            self.sub_m(&m);
            self.swap_b_c();
            self.w += Wrapping(1);
        }
    }
}

impl OutputSizeUser for ShabalVarCore {
    type OutputSize = U64;
}

impl VariableOutputCore for ShabalVarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;

    #[inline]
    #[allow(clippy::needless_range_loop)]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let init = match output_size {
            24 => consts::INIT_192,
            28 => consts::INIT_224,
            32 => consts::INIT_256,
            48 => consts::INIT_384,
            64 => consts::INIT_512,
            _ => return Err(InvalidOutputSize),
        };
        let w = Wrapping(1);
        // TODO: use `array::map` on MSRV bump
        let mut a = [Wrapping(0u32); 12];
        let mut b = [Wrapping(0u32); 16];
        let mut c = [Wrapping(0u32); 16];
        for i in 0..12 {
            a[i] = Wrapping(init.0[i]);
        }
        for i in 0..16 {
            b[i] = Wrapping(init.1[i]);
            c[i] = Wrapping(init.2[i]);
        }
        Ok(Self { a, b, c, w })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        let block = buffer.pad_with_zeros();
        block[pos] = 0x80;

        let m = read_m(block);
        self.add_m(&m);
        self.xor_w();
        self.perm(&m);
        for _ in 0..3 {
            self.swap_b_c();
            self.xor_w();
            self.perm(&m);
        }

        for (chunk, v) in out.chunks_exact_mut(4).zip(self.b.iter()) {
            chunk.copy_from_slice(&v.0.to_le_bytes());
        }
    }
}

impl AlgorithmName for ShabalVarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Shabal")
    }
}

impl fmt::Debug for ShabalVarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShabalVarCore { ... }")
    }
}

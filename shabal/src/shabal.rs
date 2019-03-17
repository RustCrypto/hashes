use block_buffer::block_padding::Iso7816;
use block_buffer::byteorder::{ByteOrder, LE};
use block_buffer::BlockBuffer;
use digest::generic_array::typenum::{U24, U28, U32, U48, U64};
use digest::generic_array::GenericArray;
pub use digest::{impl_write, Digest};
use digest::{BlockInput, FixedOutput, Input, Reset};
use opaque_debug::impl_opaque_debug;

use consts::{
    A_INIT_192, A_INIT_224, A_INIT_256, A_INIT_384, A_INIT_512, B_INIT_192, B_INIT_224, B_INIT_256,
    B_INIT_384, B_INIT_512, C_INIT_192, C_INIT_224, C_INIT_256, C_INIT_384, C_INIT_512,
};

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;

/// A structure that represents that state of a digest computation for the
/// Shabal family of digest functions
#[derive(Clone)]
struct EngineState {
    a: [u32; 12],
    b: [u32; 16],
    c: [u32; 16],
    whigh: u32,
    wlow: u32,
}

impl EngineState {
    fn new(a: &[u32; 12], b: &[u32; 16], c: &[u32; 16]) -> Self {
        Self {
            a: *a,
            b: *b,
            c: *c,
            wlow: 1,
            whigh: 0,
        }
    }

    fn process_block(&mut self, block: &Block) {
        let block = unsafe { &*(block.as_ptr() as *const [u8; 64]) };
        compress(self, block);
    }

    fn process_final_block(&mut self, block: &Block) {
        let block = unsafe { &*(block.as_ptr() as *const [u8; 64]) };
        compress_final(self, block);
    }

    #[inline]
    fn add_m(&mut self, m: &[u32; 16]) {
        for (b, m) in self.b.iter_mut().zip(m) {
            *b = b.wrapping_add(*m);
        }
    }

    #[inline]
    fn sub_m(&mut self, m: &[u32; 16]) {
        for (c, m) in self.c.iter_mut().zip(m) {
            *c = c.wrapping_sub(*m);
        }
    }

    #[inline]
    fn inc_w(&mut self) {
        self.wlow = self.wlow.wrapping_add(1);
        if self.wlow == 0 {
            self.whigh = self.whigh.wrapping_add(1);
        }
    }

    #[inline]
    fn xor_w(&mut self) {
        self.a[0] ^= self.wlow;
        self.a[1] ^= self.whigh;
    }

    #[inline]
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

    #[inline]
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
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

    #[inline]
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

    #[inline]
    fn swap_b_c(&mut self) {
        core::mem::swap(&mut self.b, &mut self.c);
    }
}

/// A structure that keeps track of the state of the Shabal operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone)]
struct Engine256 {
    buffer: BlockBuffer<BlockSize>,
    state: EngineState,
}

impl Engine256 {
    fn new(a: &[u32; 12], b: &[u32; 16], c: &[u32; 16]) -> Engine256 {
        Engine256 {
            buffer: Default::default(),
            state: EngineState::new(a, b, c),
        }
    }

    fn input(&mut self, input: &[u8]) {
        let state = &mut self.state;
        self.buffer.input(input, |input| state.process_block(input));
    }

    fn finish(&mut self) {
        let state = &mut self.state;
        let block = self.buffer.pad_with::<Iso7816>().unwrap();
        state.process_final_block(block);
    }

    fn reset(&mut self, a: &[u32; 12], b: &[u32; 16], c: &[u32; 16]) {
        self.state = EngineState::new(a, b, c);
        self.buffer.reset();
    }
}

/// The Shabal hash algorithm with the Shabal-512 initial hash value.
#[derive(Clone)]
pub struct Shabal512 {
    engine: Engine256,
}

impl Default for Shabal512 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_512, &B_INIT_512, &C_INIT_512),
        }
    }
}

impl BlockInput for Shabal512 {
    type BlockSize = BlockSize;
}

impl Input for Shabal512 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal512 {
    type OutputSize = U64;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[0..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal512 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_512, &B_INIT_512, &C_INIT_512);
    }
}

/// The Shabal hash algorithm with the Shabal-384 initial hash value. The result
/// is truncated to 384 bits.
#[derive(Clone)]
pub struct Shabal384 {
    engine: Engine256,
}

impl Default for Shabal384 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_384, &B_INIT_384, &C_INIT_384),
        }
    }
}

impl BlockInput for Shabal384 {
    type BlockSize = BlockSize;
}

impl Input for Shabal384 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal384 {
    type OutputSize = U48;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[4..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal384 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_384, &B_INIT_384, &C_INIT_384);
    }
}

/// The Shabal hash algorithm with the Shabal-256 initial hash value. The result
/// is truncated to 256 bits.
#[derive(Clone)]
pub struct Shabal256 {
    engine: Engine256,
}

impl Default for Shabal256 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_256, &B_INIT_256, &C_INIT_256),
        }
    }
}

impl BlockInput for Shabal256 {
    type BlockSize = BlockSize;
}

impl Input for Shabal256 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal256 {
    type OutputSize = U32;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[8..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal256 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_256, &B_INIT_256, &C_INIT_256);
    }
}

/// The Shabal hash algorithm with the Shabal-224 initial hash value. The result
/// is truncated to 224 bits.
#[derive(Clone)]
pub struct Shabal224 {
    engine: Engine256,
}

impl Default for Shabal224 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_224, &B_INIT_224, &C_INIT_224),
        }
    }
}

impl BlockInput for Shabal224 {
    type BlockSize = BlockSize;
}

impl Input for Shabal224 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal224 {
    type OutputSize = U28;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[9..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal224 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_224, &B_INIT_224, &C_INIT_224);
    }
}

/// The Shabal hash algorithm with the Shabal-192 initial hash value. The result
/// is truncated to 192 bits.
#[derive(Clone)]
pub struct Shabal192 {
    engine: Engine256,
}

impl Default for Shabal192 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_192, &B_INIT_192, &C_INIT_192),
        }
    }
}

impl BlockInput for Shabal192 {
    type BlockSize = BlockSize;
}

impl Input for Shabal192 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal192 {
    type OutputSize = U24;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[10..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal192 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_192, &B_INIT_192, &C_INIT_192);
    }
}

impl_opaque_debug!(Shabal512);
impl_opaque_debug!(Shabal384);
impl_opaque_debug!(Shabal256);
impl_opaque_debug!(Shabal224);
impl_opaque_debug!(Shabal192);

impl_write!(Shabal512);
impl_write!(Shabal384);
impl_write!(Shabal256);
impl_write!(Shabal224);
impl_write!(Shabal192);

#[inline]
fn read_m(input: &[u8; 64]) -> [u32; 16] {
    let mut m = [0; 16];
    LE::read_u32_into(input, &mut m);
    m
}

fn compress(state: &mut EngineState, input: &[u8; 64]) {
    let m = read_m(input);
    state.add_m(&m);
    state.xor_w();
    state.perm(&m);
    state.sub_m(&m);
    state.swap_b_c();
    state.inc_w();
}

fn compress_final(state: &mut EngineState, input: &[u8; 64]) {
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

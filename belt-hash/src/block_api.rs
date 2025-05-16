use belt_block::belt_block_raw;
use core::fmt;
use digest::{
    HashMarker, Output,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U32, U64, Unsigned},
};

const H0: [u32; 8] = [
    0xC8BA94B1, 0x3BF5080A, 0x8E006D36, 0xE45D4A58, 0x9DFA0485, 0xACC7B61B, 0xC2722E25, 0x0DCEFD02,
];

/// Core BelT hasher state.
#[derive(Clone)]
pub struct BeltHashCore {
    r: u128,
    s: [u32; 4],
    h: [u32; 8],
}

impl BeltHashCore {
    fn compress_block(&mut self, block: &Block<Self>) {
        let x1 = read_u32s(&block[..16]);
        let x2 = read_u32s(&block[16..]);
        let (t, h) = belt_compress(x1, x2, self.h);
        self.h = h;
        self.s = xor(self.s, t);
    }
}

impl HashMarker for BeltHashCore {}

impl BlockSizeUser for BeltHashCore {
    type BlockSize = U32;
}

impl BufferKindUser for BeltHashCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for BeltHashCore {
    type OutputSize = U32;
}

impl UpdateCore for BeltHashCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.r = self.r.wrapping_add(blocks.len() as u128);
        for block in blocks {
            self.compress_block(block);
        }
    }
}

impl FixedOutputCore for BeltHashCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        if pos != 0 {
            let block = buffer.pad_with_zeros();
            self.compress_block(&block);
        }
        let bs = Self::BlockSize::USIZE as u128;
        let r = encode_r(8 * ((bs * self.r) + pos as u128));
        let (_, y) = belt_compress(r, self.s, self.h);
        write_u32s(&y, out);
    }
}

impl Default for BeltHashCore {
    #[inline]
    fn default() -> Self {
        Self {
            r: 0,
            s: [0; 4],
            h: H0,
        }
    }
}

impl Reset for BeltHashCore {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for BeltHashCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltHash")
    }
}

impl fmt::Debug for BeltHashCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltHashCore { ... }")
    }
}

impl Drop for BeltHashCore {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.r.zeroize();
            self.s.zeroize();
            self.h.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for BeltHashCore {}

impl SerializableState for BeltHashCore {
    type SerializedStateSize = U64;

    fn serialize(&self) -> SerializedState<Self> {
        let mut dst = SerializedState::<Self>::default();

        let (r_dst, tail) = dst.split_at_mut(16);
        let (s_dst, h_dst) = tail.split_at_mut(16);

        r_dst.copy_from_slice(&self.r.to_le_bytes());
        write_u32s(&self.s, s_dst);
        write_u32s(&self.h, h_dst);

        dst
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (r_src, tail) = serialized_state.split_at(16);
        let (s_src, h_src) = tail.split_at(16);

        Ok(Self {
            r: u128::from_le_bytes(r_src.try_into().unwrap()),
            s: read_u32s(s_src),
            h: read_u32s(h_src),
        })
    }
}

/// Compression function described in the section 6.3.2
#[inline(always)]
pub fn belt_compress(x1: [u32; 4], x2: [u32; 4], x34: [u32; 8]) -> ([u32; 4], [u32; 8]) {
    let x3 = [x34[0], x34[1], x34[2], x34[3]];
    let x4 = [x34[4], x34[5], x34[6], x34[7]];

    // Step 2
    let t1 = belt_block_raw(xor(x3, x4), &concat(x1, x2));
    let s = xor(xor(t1, x3), x4);
    // Step 3
    let t2 = belt_block_raw(x1, &concat(s, x4));
    let y1 = xor(t2, x1);
    // Step 4
    let t3 = belt_block_raw(x2, &concat(s.map(|v| !v), x3));
    let y2 = xor(t3, x2);
    // Step 5
    (s, concat(y1, y2))
}

#[inline(always)]
fn xor(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

#[inline(always)]
fn concat(a: [u32; 4], b: [u32; 4]) -> [u32; 8] {
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

#[inline(always)]
fn read_u32s<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(src.len(), 4 * N);

    let mut dst = [0u32; N];
    for (dst, src) in dst.iter_mut().zip(src.chunks_exact(4)) {
        *dst = u32::from_le_bytes(src.try_into().unwrap());
    }
    dst
}

#[inline(always)]
fn write_u32s(src: &[u32], dst: &mut [u8]) {
    assert_eq!(4 * src.len(), dst.len());
    for (src, dst) in src.iter().zip(dst.chunks_exact_mut(4)) {
        dst.copy_from_slice(&src.to_le_bytes());
    }
}

#[inline(always)]
fn encode_r(r: u128) -> [u32; 4] {
    core::array::from_fn(|i| (r >> (32 * i)) as u32)
}

#[cfg(test)]
mod tests {
    use super::{belt_compress, read_u32s};
    use hex_literal::hex;

    /// Test vectors for the `belt-compress` functions from the
    /// specification (Table A.8).
    #[test]
    fn compress() {
        let x = &hex!(
            "B194BAC8 0A08F53B 366D008E 584A5DE4"
            "8504FA9D 1BB6C7AC 252E72C2 02FDCE0D"
            "5BE3D612 17B96181 FE6786AD 716B890B"
            "5CB0C0FF 33C356B8 35C405AE D8E07F99"
        );
        let expected_s = &hex!("46FE7425 C9B181EB 41DFEE3E 72163D5A");
        let expected_y = &hex!(
            "ED2F5481 D593F40D 87FCE37D 6BC1A2E1"
            "B7D1A2CC 975C82D3 C0497488 C90D99D8"
        );
        let x1 = read_u32s(&x[..16]);
        let x2 = read_u32s(&x[16..32]);
        let x34 = read_u32s(&x[32..]);

        let (s, y) = belt_compress(x1, x2, x34);

        assert_eq!(s, read_u32s(expected_s));
        assert_eq!(y, read_u32s(expected_y));
    }
}

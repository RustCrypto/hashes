use core::array;

#[inline(always)]
pub(crate) fn xor<const N: usize>(a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut result = [0u64; N];
    for i in 0..N {
        result[i] = a[i] ^ b[i];
    }
    result
}

#[inline(always)]
pub(crate) fn read_u64_le<const N: usize, const M: usize>(src: &[u8; N]) -> [u64; M] {
    assert_eq!(N, 8 * M);
    let mut res = [0; M];
    for (src, dst) in src.chunks_exact(8).zip(res.iter_mut()) {
        *dst = u64::from_le_bytes(src.try_into().unwrap());
    }
    res
}

#[inline(always)]
pub(crate) fn write_u64_le(src: &[u64], dst: &mut [u8]) {
    assert_eq!(8 * src.len(), dst.len());
    for (src, dst) in src.iter().zip(dst.chunks_exact_mut(8)) {
        dst.copy_from_slice(&src.to_le_bytes())
    }
}

#[inline(always)]
pub(crate) fn write_u64_be(src: &[u64], dst: &mut [u8]) {
    assert_eq!(8 * src.len(), dst.len());
    for (src, dst) in src.iter().zip(dst.chunks_exact_mut(8)) {
        dst.copy_from_slice(&src.to_be_bytes())
    }
}

#[inline(always)]
pub(crate) fn read_u64s_be<const N: usize, const M: usize>(block: &[u8; N]) -> [u64; M] {
    array::from_fn(|i| {
        let chunk = block[8 * i..][..8].try_into().unwrap();
        u64::from_be_bytes(chunk)
    })
}

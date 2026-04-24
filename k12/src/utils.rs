use keccak::State1600;

pub(crate) fn xor_block(state: &mut State1600, block: &[u8]) {
    debug_assert!(size_of_val(block) < size_of_val(state));

    let mut chunks = block.chunks_exact(size_of::<u64>());
    for (s, chunk) in state.iter_mut().zip(&mut chunks) {
        *s ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }

    let rem = chunks.remainder();
    debug_assert!(
        rem.is_empty(),
        "block size should be multiple of `size_of::<u64>()"
    );
}

pub(crate) fn copy_cv(state: &State1600, cv_dst: &mut [u8]) {
    let mut chunks = cv_dst.chunks_exact_mut(size_of::<u64>());
    for (src, dst) in state.iter().zip(&mut chunks) {
        dst.copy_from_slice(&src.to_le_bytes());
    }
    assert!(chunks.into_remainder().is_empty());
}

pub(crate) fn length_encode(len: u64, f: impl FnOnce(&[u8])) {
    let mut buf = [0u8; 9];
    buf[..8].copy_from_slice(&len.to_be_bytes());
    buf[8] = u8::try_from((u64::BITS - len.leading_zeros()).div_ceil(8))
        .expect("the division result can not be bigger than 8");
    let idx = 8 - usize::from(buf[8]);
    let enc_len = &buf[idx..];
    f(enc_len);
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    #[test]
    fn length_encode() {
        use super::length_encode;

        length_encode(0, |r| assert_eq!(r, hex!("00")));
        length_encode(1, |r| assert_eq!(r, hex!("0101")));
        length_encode(12, |r| assert_eq!(r, hex!("0C01")));
        length_encode((1 << 16) - 1, |r| assert_eq!(r, hex!("ffff02")));
        length_encode(1 << 16, |r| assert_eq!(r, hex!("01000003")));
        length_encode(65538, |r| assert_eq!(r, hex!("01000203")));
        length_encode((1 << 32) - 1, |r| assert_eq!(r, hex!("ffffffff04")));
        length_encode(1 << 32, |r| assert_eq!(r, hex!("010000000005")));
    }
}

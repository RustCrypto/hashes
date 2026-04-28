cfg_if::cfg_if! {
    if #[cfg(sha2_backend_soft = "compact")] {
        mod compact;
        pub(super) use compact::compress;
    } else {
        mod unroll;
        pub(super) use unroll::compress;
    }
}

#[inline(always)]
fn to_u64s(block: &[u8; 128]) -> [u64; 16] {
    core::array::from_fn(|i| {
        let chunk = block[8 * i..][..8].try_into().unwrap();
        u64::from_be_bytes(chunk)
    })
}

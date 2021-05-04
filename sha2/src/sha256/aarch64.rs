#[cfg(target_os = "linux")]
#[inline(always)]
pub fn sha2_supported() -> bool {
    use libc::{getauxval, AT_HWCAP, HWCAP_SHA2};

    let hwcaps: u64 = unsafe { getauxval(AT_HWCAP) };
    (hwcaps & HWCAP_SHA2) != 0
}

#[cfg(target_os = "macos")]
#[inline(always)]
pub fn sha2_supported() -> bool {
    // TODO: Use cpufeatures once support lands
    true
}

pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // TODO: Replace with https://github.com/rust-lang/rfcs/pull/2725
    // after stabilization
    if sha2_supported() {
        sha2_asm::compress256(state, blocks);
    } else {
        super::soft::compress(state, blocks);
    }
}

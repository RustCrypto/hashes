use libc::{getauxval, AT_HWCAP, HWCAP_SHA1};

#[inline(always)]
pub fn sha1_supported() -> bool {
    let hwcaps: u64 = unsafe { getauxval(AT_HWCAP) };
    (hwcaps & HWCAP_SHA1) != 0
}

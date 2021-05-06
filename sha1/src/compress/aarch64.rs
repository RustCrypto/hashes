//! SHA-1 `aarch64` backend.

/// Per rustc target feature docs for `aarch64-unknown-linux-gnu` and
/// `aarch64-apple-darwin` platforms, the `sha2` target feature enables
/// SHA-1 as well:
///
/// > Enable SHA1 and SHA256 support.
cpufeatures::new!(sha2_hwcap, "sha2");

pub fn compress(state: &mut [u32; 5], blocks: &[u8; 64]) {
    // TODO: Replace with https://github.com/rust-lang/rfcs/pull/2725
    // after stabilization
    if sha2_hwcap::get() {
        for block in blocks {
            sha1_asm::compress(state, block);
        }
    } else {
        super::soft::compress(state, blocks);
    }
}

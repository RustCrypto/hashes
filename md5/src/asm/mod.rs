#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod x86;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub use x86::compress_block;

#[inline]
pub fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block)
    }
}

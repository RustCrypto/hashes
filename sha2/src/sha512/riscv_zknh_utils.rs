use core::{arch::asm, ptr};

#[inline(always)]
pub(super) fn load_block(block: &[u8; 128]) -> [u64; 16] {
    if block.as_ptr().cast::<usize>().is_aligned() {
        load_aligned_block(block)
    } else {
        load_unaligned_block(block)
    }
}

#[cfg(target_arch = "riscv32")]
fn load_aligned_block(block: &[u8; 128]) -> [u64; 16] {
    let p: *const [u32; 32] = block.as_ptr().cast();
    debug_assert!(p.is_aligned());
    let block = unsafe { &*p };
    let mut res = [0u64; 16];
    for i in 0..16 {
        let a = block[2 * i].to_be() as u64;
        let b = block[2 * i + 1].to_be() as u64;
        res[i] = (a << 32) | b;
    }
    res
}

#[cfg(target_arch = "riscv64")]
fn load_aligned_block(block: &[u8; 128]) -> [u64; 16] {
    let block_ptr: *const u64 = block.as_ptr().cast();
    debug_assert!(block_ptr.is_aligned());
    let mut res = [0u64; 16];
    for i in 0..16 {
        let val = unsafe { ptr::read(block_ptr.add(i)) };
        res[i] = val.to_be();
    }
    res
}

#[cfg(target_arch = "riscv32")]
fn load_unaligned_block(block: &[u8; 128]) -> [u64; 16] {
    let offset = (block.as_ptr() as usize) % align_of::<u32>();
    debug_assert_ne!(offset, 0);
    let off1 = (8 * offset) % 32;
    let off2 = (32 - off1) % 32;
    let bp: *const u32 = block.as_ptr().wrapping_sub(offset).cast();

    let mut left: u32;
    let mut block32 = [0u32; 32];

    unsafe {
        asm!(
            "lw {left}, 0({bp})",         // left = unsafe { ptr::read(bp) };
            "srl {left}, {left}, {off1}", // left >>= off1;
            bp = in(reg) bp,
            off1 = in(reg) off1,
            left = out(reg) left,
            options(pure, nostack, readonly, preserves_flags),
        );
    }

    for i in 0..31 {
        let right = unsafe { ptr::read(bp.add(1 + i)) };
        block32[i] = left | (right << off2);
        left = right >> off1;
    }

    let right: u32;
    unsafe {
        asm!(
            "lw {right}, 32 * 4({bp})",     // right = ptr::read(bp.add(32));
            "sll {right}, {right}, {off2}", // right <<= off2;
            bp = in(reg) bp,
            off2 = in(reg) off2,
            right = out(reg) right,
            options(pure, nostack, readonly, preserves_flags),
        );
    }
    block32[31] = left | right;

    let mut block64 = [0u64; 16];
    for i in 0..16 {
        let a = block32[2 * i].to_be() as u64;
        let b = block32[2 * i + 1].to_be() as u64;
        block64[i] = (a << 32) | b;
    }
    block64
}

#[cfg(target_arch = "riscv64")]
fn load_unaligned_block(block: &[u8; 128]) -> [u64; 16] {
    let offset = (block.as_ptr() as usize) % align_of::<u64>();
    debug_assert_ne!(offset, 0);
    let off1 = (8 * offset) % 64;
    let off2 = (64 - off1) % 64;
    let bp: *const u64 = block.as_ptr().wrapping_sub(offset).cast();

    let mut left: u64;
    let mut res = [0u64; 16];

    unsafe {
        asm!(
            "ld {left}, 0({bp})",           // left = unsafe { ptr::read(bp) };
            "srl {left}, {left}, {off1}",   // left >>= off1;
            bp = in(reg) bp,
            off1 = in(reg) off1,
            left = out(reg) left,
            options(pure, nostack, readonly, preserves_flags),
        );
    }
    for i in 0..15 {
        let right = unsafe { ptr::read(bp.add(1 + i)) };
        res[i] = (left | (right << off2)).to_be();
        left = right >> off1;
    }

    let right: u64;
    unsafe {
        asm!(
            "ld {right}, 16 * 8({bp})",     // right = ptr::read(bp.add(16));
            "sll {right}, {right}, {off2}", // right <<= off2;
            bp = in(reg) bp,
            off2 = in(reg) off2,
            right = out(reg) right,
            options(pure, nostack, readonly, preserves_flags),
        );
    }
    res[15] = (left | right).to_be();

    res
}

/// This function returns `k[R]`, but prevents compiler from inlining the indexed value
#[cfg(sha2_backend = "riscv-zknh")]
pub(super) fn opaque_load<const R: usize>(k: &[u64]) -> u64 {
    assert!(R < k.len());
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let dst;
        asm!(
            "ld {dst}, 8 * {R}({k})",
            R = const R,
            k = in(reg) k.as_ptr(),
            dst = out(reg) dst,
            options(pure, readonly, nostack, preserves_flags),
        );
        dst
    }
    #[cfg(target_arch = "riscv32")]
    unsafe {
        let [hi, lo]: [u32; 2];
        asm!(
            "lw {lo}, 8 * {R}({k})",
            "lw {hi}, 8 * {R} + 4({k})",
            R = const R,
            k = in(reg) k.as_ptr(),
            lo = out(reg) lo,
            hi = out(reg) hi,
            options(pure, readonly, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

use core::{arch::asm, ptr};

#[inline(always)]
pub(super) fn load_block(block: &[u8; 64]) -> [u32; 16] {
    if block.as_ptr().cast::<u32>().is_aligned() {
        load_aligned_block(block)
    } else {
        load_unaligned_block(block)
    }
}

#[inline(always)]
fn load_aligned_block(block: &[u8; 64]) -> [u32; 16] {
    let p: *const u32 = block.as_ptr().cast();
    debug_assert!(p.is_aligned());
    let mut res = [0u32; 16];
    for i in 0..16 {
        let val = unsafe { ptr::read(p.add(i)) };
        res[i] = val.to_be();
    }
    res
}

#[inline(always)]
fn load_unaligned_block(block: &[u8; 64]) -> [u32; 16] {
    let offset = (block.as_ptr() as usize) % align_of::<u32>();
    debug_assert_ne!(offset, 0);
    let off1 = (8 * offset) % 32;
    let off2 = (32 - off1) % 32;
    let bp: *const u32 = block.as_ptr().wrapping_sub(offset).cast();

    let mut left: u32;
    let mut res = [0u32; 16];

    /// Use LW instruction on RV32 and LWU on RV64
    #[cfg(target_arch = "riscv32")]
    macro_rules! lw {
        ($r:literal) => {
            concat!("lw ", $r)
        };
    }
    #[cfg(target_arch = "riscv64")]
    macro_rules! lw {
        ($r:literal) => {
            concat!("lwu ", $r)
        };
    }

    unsafe {
        asm!(
            lw!("{left}, 0({bp})"),         // left = unsafe { ptr::read(bp) };
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

    let right: u32;
    unsafe {
        asm!(
            lw!("{right}, 16 * 4({bp})"),   // right = ptr::read(bp.add(16));
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

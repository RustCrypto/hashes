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
fn sig0(w: u32) -> u32 {
    (w.rotate_right(7)) ^ (w.rotate_right(18)) ^ (w >> 3)
}

#[inline(always)]
fn sig1(w: u32) -> u32 {
    (w.rotate_right(17)) ^ (w.rotate_right(19)) ^ (w >> 10)
}

#[inline(always)]
fn sum0(w: u32) -> u32 {
    w.rotate_right(2) ^ w.rotate_right(13) ^ w.rotate_right(22)
}

#[inline(always)]
fn sum1(w: u32) -> u32 {
    w.rotate_right(6) ^ w.rotate_right(11) ^ w.rotate_right(25)
}

#[inline(always)]
fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ ((!e) & g)
}

#[inline(always)]
fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

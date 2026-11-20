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
fn sig0(w: u64) -> u64 {
    (w.rotate_right(1)) ^ (w.rotate_right(8)) ^ (w >> 7)
}

#[inline(always)]
fn sig1(w: u64) -> u64 {
    (w.rotate_right(19)) ^ (w.rotate_right(61)) ^ (w >> 6)
}

#[inline(always)]
fn sum0(w: u64) -> u64 {
    w.rotate_right(28) ^ w.rotate_right(34) ^ w.rotate_right(39)
}

#[inline(always)]
fn sum1(w: u64) -> u64 {
    w.rotate_right(14) ^ w.rotate_right(18) ^ w.rotate_right(41)
}

#[inline(always)]
fn ch(e: u64, f: u64, g: u64) -> u64 {
    (e & f) ^ ((!e) & g)
}

#[inline(always)]
fn maj(a: u64, b: u64, c: u64) -> u64 {
    (a & b) ^ (a & c) ^ (b & c)
}

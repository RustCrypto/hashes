#![allow(non_upper_case_globals)]

use core::ptr;
use digest::generic_array::{typenum::U64, GenericArray};
use simd::{dispatch, vec128_storage, AndNot, Machine, Swap64, VZip, Vec2};

#[rustfmt::skip]
macro_rules! unroll7 {
    ($j:ident, $body:block) => {
        { const $j: usize = 0; $body }
        { const $j: usize = 1; $body }
        { const $j: usize = 2; $body }
        { const $j: usize = 3; $body }
        { const $j: usize = 4; $body }
        { const $j: usize = 5; $body }
        { const $j: usize = 6; $body }
    };
}

#[repr(C)]
#[derive(Copy, Clone)]
struct X8<M: Machine>(
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
);

impl<M: Machine> X8<M> {
    #[inline(always)]
    fn zip(self) -> (M::u128x2, M::u128x2, M::u128x2, M::u128x2) {
        (
            [self.0, self.1].vzip(),
            [self.2, self.3].vzip(),
            [self.4, self.5].vzip(),
            [self.6, self.7].vzip(),
        )
    }

    #[inline(always)]
    fn unzip((a, b, c, d): (M::u128x2, M::u128x2, M::u128x2, M::u128x2)) -> Self {
        X8(
            a.extract(0),
            a.extract(1),
            b.extract(0),
            b.extract(1),
            c.extract(0),
            c.extract(1),
            d.extract(0),
            d.extract(1),
        )
    }
}

/// two Sboxes computed in parallel; each Sbox implements S0 and S1, selected by a constant bit
#[inline(always)]
fn ss<M: Machine>(state: X8<M>, mut k: M::u128x2) -> X8<M> {
    let mut m = state.zip();
    // TODO: replace ! with andnot ops?
    m.3 = !m.3;
    m.0 ^= m.2.andnot(k);
    k ^= m.0 & m.1;
    m.0 ^= m.3 & m.2;
    m.3 ^= m.1.andnot(m.2);
    m.1 ^= m.0 & m.2;
    m.2 ^= m.3.andnot(m.0);
    m.0 ^= m.1 | m.3;
    m.3 ^= m.1 & m.2;
    m.2 ^= k;
    m.1 ^= k & m.0;
    X8::unzip(m)
}

#[inline(always)]
fn l<M: Machine>(mut y: X8<M>) -> X8<M> {
    y.1 ^= y.2;
    y.3 ^= y.4;
    y.5 ^= y.6 ^ y.0;
    y.7 ^= y.0;
    y.0 ^= y.3;
    y.2 ^= y.5;
    y.4 ^= y.7 ^ y.1;
    y.6 ^= y.1;
    y
}

union X2Bytes<M: Machine> {
    x2: M::u128x2,
    bytes: [u8; 32],
}

#[inline(always)]
#[doc(hidden)]
pub fn f8_impl<M: Machine>(mach: M, state: &mut [vec128_storage; 8], data: *const u8) {
    #[allow(clippy::cast_ptr_alignment)]
    let data = data as *const M::u128x1;
    let mut y = X8::<M>(
        mach.unpack(state[0]),
        mach.unpack(state[1]),
        mach.unpack(state[2]),
        mach.unpack(state[3]),
        mach.unpack(state[4]),
        mach.unpack(state[5]),
        mach.unpack(state[6]),
        mach.unpack(state[7]),
    );
    unsafe {
        y.0 ^= ptr::read_unaligned(data);
        y.1 ^= ptr::read_unaligned(data.offset(1));
        y.2 ^= ptr::read_unaligned(data.offset(2));
        y.3 ^= ptr::read_unaligned(data.offset(3));
    }
    for rc in crate::consts::E8_BITSLICE_ROUNDCONSTANT.chunks_exact(7) {
        unroll7!(j, {
            y = ss(y, unsafe { X2Bytes::<M> { bytes: rc[j] }.x2 });
            y = l(y);
            let f = match j {
                0 => M::u128x1::swap1,
                1 => M::u128x1::swap2,
                2 => M::u128x1::swap4,
                3 => M::u128x1::swap8,
                4 => M::u128x1::swap16,
                5 => M::u128x1::swap32,
                6 => M::u128x1::swap64,
                _ => unreachable!(),
            };
            y = X8(y.0, f(y.1), y.2, f(y.3), y.4, f(y.5), y.6, f(y.7));
        });
    }
    unsafe {
        y.4 ^= ptr::read_unaligned(data);
        y.5 ^= ptr::read_unaligned(data.offset(1));
        y.6 ^= ptr::read_unaligned(data.offset(2));
        y.7 ^= ptr::read_unaligned(data.offset(3));
    }
    *state = [
        y.0.into(),
        y.1.into(),
        y.2.into(),
        y.3.into(),
        y.4.into(),
        y.5.into(),
        y.6.into(),
        y.7.into(),
    ];
}

dispatch!(mach, M, {
    fn f8(state: &mut [vec128_storage; 8], data: *const u8) {
        f8_impl(mach, state, data);
    }
});

pub(crate) union Compressor {
    cv: [vec128_storage; 8],
    bytes: [u8; 128],
}

impl Compressor {
    #[inline]
    pub(crate) fn new(bytes: [u8; 128]) -> Self {
        Compressor { bytes }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &GenericArray<u8, U64>) {
        f8(unsafe { &mut self.cv }, data.as_ptr());
    }

    #[inline]
    pub(crate) fn finalize(&self) -> &[u8; 128] {
        unsafe { &self.bytes }
    }
}

impl Clone for Compressor {
    fn clone(&self) -> Self {
        Self {
            bytes: unsafe { self.bytes },
        }
    }
}

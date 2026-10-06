#![allow(clippy::needless_range_loop)]
use core::ops::{AddAssign, BitXor, BitXorAssign};

#[cfg(feature = "zeroize")]
use digest::zeroize::Zeroize;

#[derive(Clone, Copy, Default)]
pub(crate) struct U512(pub(crate) [u64; 8]);

impl U512 {
    pub(crate) const ZERO: Self = U512([0; 8]);

    #[inline(always)]
    pub(crate) fn to_bytes(self) -> [u8; 64] {
        let mut t = [0; 64];
        for (chunk, v) in t.chunks_exact_mut(8).zip(self.0.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
        t
    }

    #[inline(always)]
    pub(crate) fn from_bytes(b: &[u8; 64]) -> Self {
        let mut t = [0u64; 8];
        for (v, chunk) in t.iter_mut().zip(b.chunks_exact(8)) {
            *v = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Self(t)
    }
}

impl BitXor<&U512> for U512 {
    type Output = U512;
    #[inline(always)]
    fn bitxor(self, rhs: &U512) -> U512 {
        let buf = core::array::from_fn(|i| self.0[i] ^ rhs.0[i]);
        U512(buf)
    }
}

impl BitXorAssign<&U512> for U512 {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: &U512) {
        for i in 0..8 {
            self.0[i] ^= rhs.0[i];
        }
    }
}

impl BitXorAssign for U512 {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: U512) {
        for i in 0..8 {
            self.0[i] ^= rhs.0[i];
        }
    }
}

impl AddAssign<U512> for U512 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        let mut carry = false;
        for i in 0..8 {
            adc(&mut self.0[i], rhs.0[i], &mut carry);
        }
    }
}

impl AddAssign<u64> for U512 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: u64) {
        let mut carry = false;
        adc(&mut self.0[0], rhs, &mut carry);
        for i in 1..8 {
            adc(&mut self.0[i], 0, &mut carry);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for U512 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// This function mirrors implementation of the `carrying_add` method:
// https://github.com/rust-lang/rust/blob/9cdfe28/library/core/src/num/uint_macros.rs#L2060-L2066
#[inline(always)]
fn adc(v1: &mut u64, v2: u64, carry: &mut bool) {
    let (a, b) = v1.overflowing_add(v2);
    let (c, d) = a.overflowing_add(*carry as u64);
    *v1 = c;
    *carry = b || d;
}

//$result

macro_rules! blake2_impl {
    ($state:ident, $word:ident, $vec:ident,
     $bytes:ident, $R1:expr, $R2:expr, $R3:expr, $R4:expr,
     $IV:expr) => {

        use $crate::as_bytes::AsBytes;
        use $crate::bytes::BytesExt;
        use $crate::simd::{Vector4, $vec};

        use generic_array::{GenericArray, ArrayLength};
        use core::marker::PhantomData;
        use core::cmp;
        use byte_tools::copy_memory;
        use generic_array::typenum::Unsigned;
        use digest::Digest;

        /// State context.
        #[derive(Clone, Debug)]
        // TODO: encode  assert!(nn >= 1 && nn <= $bytes && kk <= $bytes);
        pub struct $state<N> where N: ArrayLength<u8> + Copy {
            m: [$word; 16],
            h: [$vec; 2],
            t: u64,
            phantom: PhantomData<N>,
        }

        #[inline(always)]
        fn iv0() -> $vec { $vec::new($IV[0], $IV[1], $IV[2], $IV[3]) }
        #[inline(always)]
        fn iv1() -> $vec { $vec::new($IV[4], $IV[5], $IV[6], $IV[7]) }

        #[inline(always)]
        fn quarter_round(v: &mut [$vec; 4], rd: u32, rb: u32, m: $vec) {
            v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
            v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
            v[2] = v[2].wrapping_add(v[3]);
            v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
        }

        #[inline(always)]
        fn shuffle(v: &mut [$vec; 4]) {
            v[1] = v[1].shuffle_left_1();
            v[2] = v[2].shuffle_left_2();
            v[3] = v[3].shuffle_left_3();
        }

        #[inline(always)]
        fn unshuffle(v: &mut [$vec; 4]) {
            v[1] = v[1].shuffle_right_1();
            v[2] = v[2].shuffle_right_2();
            v[3] = v[3].shuffle_right_3();
        }

        #[inline(always)]
        fn round(v: &mut [$vec; 4], m: &[$word; 16], s: &[usize; 16]) {
            quarter_round(v, $R1, $R2, $vec::gather(m,
                                  s[ 0], s[ 2], s[ 4], s[ 6]));
            quarter_round(v, $R3, $R4, $vec::gather(m,
                                  s[ 1], s[ 3], s[ 5], s[ 7]));

            shuffle(v);
            quarter_round(v, $R1, $R2, $vec::gather(m,
                                  s[ 8], s[10], s[12], s[14]));
            quarter_round(v, $R3, $R4, $vec::gather(m,
                                  s[ 9], s[11], s[13], s[15]));
            unshuffle(v);
        }
        
        impl<N> $state<N> where N: ArrayLength<u8> + Copy {
            /// Creates a new hashing context without a key.
            pub fn new() -> Self { Self::new_keyed(&[]) }

            /// Creates a new hashing context with a key.
            #[cfg_attr(feature = "clippy", allow(cast_possible_truncation))]
            pub fn new_keyed(k: &[u8]) -> Self {
                let kk = k.len();
                // TODO: encode into type
                //assert!(kk <= $bytes::to_usize());

                let p0 = 0x01010000 ^ ((kk as $word) << 8) ^
                    ($bytes::to_u64() as $word);
                let mut state = $state {
                    m: [0; 16],
                    h: [iv0() ^ $vec::new(p0, 0, 0, 0), iv1()],
                    t: 0,
                    phantom: Default::default(),
                };

                if kk > 0 {
                    state.m.as_mut_bytes().copy_bytes_from(k);
                    state.t = $bytes::to_u64() * 2;
                }
                state
            }

            #[doc(hidden)]
            #[cfg_attr(feature = "clippy", allow(cast_possible_truncation))]
            /*
            pub fn with_parameter_block(p: &[$word; 8]) -> Self {
                let nn = p[0] as u8 as usize;
                let kk = (p[0] >> 8) as u8 as usize;
                assert!(nn >= 1 && nn <= $bytes && kk <= $bytes);

                $state {
                    m: [0; 16],
                    h: [iv0() ^ $vec::new(p[0], p[1], p[2], p[3]),
                        iv1() ^ $vec::new(p[4], p[5], p[6], p[7])],
                    t: 0,
                    nn: nn,
                }
            }
            */


            /// Updates the hashing context with more data.
            #[cfg_attr(feature = "clippy", allow(cast_possible_truncation))]
            pub fn update(&mut self, data: &[u8]) {
                let mut rest = data;

                let off = (self.t % ($bytes::to_u64() * 2)) as usize;
                if off != 0 || self.t == 0 {
                    let len = cmp::min(($bytes::to_usize() * 2) - off, rest.len());

                    let part = &rest[..len];
                    rest = &rest[part.len()..];

                    self.m.as_mut_bytes()[off..].copy_bytes_from(part);
                    self.t = self.t.checked_add(part.len() as u64)
                        .expect("hash data length overflow");
                }

                while rest.len() >= $bytes::to_usize() * 2 {
                    self.compress(0, 0);

                    let part = &rest[..($bytes::to_usize() * 2)];
                    rest = &rest[part.len()..];

                    self.m.as_mut_bytes().copy_bytes_from(part);
                    self.t = self.t.checked_add(part.len() as u64)
                        .expect("hash data length overflow");
                }

                if rest.len() > 0 {
                    self.compress(0, 0);

                    self.m.as_mut_bytes().copy_bytes_from(rest);
                    self.t = self.t.checked_add(rest.len() as u64)
                        .expect("hash data length overflow");
                }
            }
            
            /// Consumes the hashing context and returns the resulting hash.
            pub fn finalize(self) -> GenericArray<u8, N> {
                self.finalize_with_flag(0)
            }

            #[cfg_attr(feature = "clippy", allow(cast_possible_truncation))]
            fn finalize_with_flag(mut self, f1: $word) -> GenericArray<u8, N> {
                let off = (self.t % ($bytes::to_u64() * 2)) as usize;
                if off != 0 {
                    self.m.as_mut_bytes()[off..].set_bytes(0);
                }

                self.compress(!0, f1);


                let buf = [self.h[0].to_le(), self.h[1].to_le()];

                let mut out = GenericArray::default();
                copy_memory(&buf.as_bytes()[..N::to_usize()], &mut out);
                out
            }

            #[cfg_attr(feature = "clippy", allow(cast_possible_truncation, eq_op))]
            fn compress(&mut self, f0: $word, f1: $word) {
                use $crate::consts::SIGMA;

                let m = &self.m;
                let h = &mut self.h;

                let t0 = self.t as $word;
                let t1 = match $bytes::to_u8() {
                    64 => 0,
                    32 => (self.t >> 32) as $word,
                    _  => unreachable!(),
                };

                let mut v = [
                    h[0],
                    h[1],
                    iv0(),
                    iv1() ^ $vec::new(t0, t1, f0, f1),
                ];

                round(&mut v, m, &SIGMA[0]);
                round(&mut v, m, &SIGMA[1]);
                round(&mut v, m, &SIGMA[2]);
                round(&mut v, m, &SIGMA[3]);
                round(&mut v, m, &SIGMA[4]);
                round(&mut v, m, &SIGMA[5]);
                round(&mut v, m, &SIGMA[6]);
                round(&mut v, m, &SIGMA[7]);
                round(&mut v, m, &SIGMA[8]);
                round(&mut v, m, &SIGMA[9]);
                if $bytes::to_u8() == 64 {
                    round(&mut v, m, &SIGMA[0]);
                    round(&mut v, m, &SIGMA[1]);
                }

                h[0] = h[0] ^ (v[0] ^ v[2]);
                h[1] = h[1] ^ (v[1] ^ v[3]);
            }

        }


        impl<N> Default for $state<N> where N: ArrayLength<u8> + Copy {
            fn default() -> Self { Self::new() }
        }

        impl<N> Digest for $state<N> where N: ArrayLength<u8> + Copy {
            type OutputSize = N;
            // TODO: change for blake2s
            type BlockSize = $bytes;

            fn input(&mut self, input: &[u8]) { self.update(input); }

            fn result(self) -> GenericArray<u8, Self::OutputSize> { self.finalize() }
        }

    }
}
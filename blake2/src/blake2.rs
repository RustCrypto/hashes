macro_rules! blake2_impl {
    ($state:ident, $word:ident, $vec:ident, $bytes:ident,
     $R1:expr, $R2:expr, $R3:expr, $R4:expr, $IV:expr) => {

        use $crate::as_bytes::AsBytes;
        use $crate::simd::{Vector4, $vec};

        use digest::generic_array::GenericArray;
        use digest::generic_array::typenum::Unsigned;
        use core::cmp;
        use byte_tools::{copy_memory, zero};
        use digest;
        use crypto_mac::{Mac, MacResult};

        type Output = GenericArray<u8, $bytes>;

        /// Hash function context.
        #[derive(Copy, Clone, Debug)]
        pub struct $state {
            m: [$word; 16],
            h: [$vec; 2],
            t: u64,
            n: usize,
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

        impl $state {
            /// Creates a new hashing context with a key.
            pub fn new_keyed(k: &[u8], output_size: usize) -> Self {
                let kk = k.len();
                assert!(kk <= $bytes::to_usize());
                assert!(output_size <= $bytes::to_usize());

                let p0 = 0x0101_0000 ^ ((kk as $word) << 8) ^
                    (output_size as $word);
                let mut state = $state {
                    m: [0; 16],
                    h: [iv0() ^ $vec::new(p0, 0, 0, 0), iv1()],
                    t: 0,
                    n: output_size,
                };

                if kk > 0 {
                    copy_memory(k, state.m.as_mut_bytes());
                    state.t = 2 * $bytes::to_u64();
                }
                state
            }

            #[doc(hidden)]
            pub fn with_parameter_block(p: &[$word; 8]) -> Self {
                let nn = p[0] as u8 as usize;
                let kk = (p[0] >> 8) as u8 as usize;
                assert!(nn >= 1 && nn <= $bytes::to_usize());
                assert!(kk <= $bytes::to_usize());

                $state {
                    m: [0; 16],
                    h: [iv0() ^ $vec::new(p[0], p[1], p[2], p[3]),
                        iv1() ^ $vec::new(p[4], p[5], p[6], p[7])],
                    t: 0,
                    n: nn,
                }
            }

            /// Updates the hashing context with more data.
            fn update(&mut self, data: &[u8]) {
                let mut rest = data;

                let block = 2 * $bytes::to_usize();

                let off = self.t as usize % block;
                if off != 0 || self.t == 0 {
                    let len = cmp::min(block - off, rest.len());

                    let part = &rest[..len];
                    rest = &rest[part.len()..];

                    copy_memory(part, &mut self.m.as_mut_bytes()[off..]);
                    self.t = self.t.checked_add(part.len() as u64)
                        .expect("hash data length overflow");
                }

                while rest.len() >= block {
                    self.compress(0, 0);

                    let part = &rest[..block];
                    rest = &rest[part.len()..];

                    copy_memory(part, &mut self.m.as_mut_bytes());
                    self.t = self.t.checked_add(part.len() as u64)
                        .expect("hash data length overflow");
                }

                let n = rest.len();
                if n > 0 {
                    self.compress(0, 0);

                    copy_memory(rest, &mut self.m.as_mut_bytes());
                    self.t = self.t.checked_add(rest.len() as u64)
                        .expect("hash data length overflow");
                }
            }

            #[doc(hidden)]
            pub fn finalize_last_node(self) -> Output {
                self.finalize_with_flag(!0)
            }


            fn finalize_with_flag(mut self, f1: $word) -> Output {
                let off = self.t as usize % (2 * $bytes::to_usize());
                if off != 0 {
                    zero(&mut self.m.as_mut_bytes()[off..]);
                }

                self.compress(!0, f1);

                let buf = [self.h[0].to_le(), self.h[1].to_le()];

                let mut out = GenericArray::default();
                copy_memory(buf.as_bytes(), &mut out);
                out
            }

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


        impl Default for $state {
            fn default() -> Self { Self::new_keyed(&[], $bytes::to_usize()) }
        }

        impl digest::BlockInput for $state {
            type BlockSize = $bytes;
        }

        impl digest::Input for $state {
            fn process(&mut self, input: &[u8]) { self.update(input); }
        }

        impl digest::FixedOutput for $state {
            type OutputSize = $bytes;

            fn fixed_result(self) -> Output {
                assert_eq!(self.n, $bytes::to_usize());
                self.finalize_with_flag(0)
            }
        }

        impl digest::VariableOutput for $state {
            fn new(output_size: usize) -> Result<Self, digest::InvalidLength> {
                if output_size == 0 || output_size > $bytes::to_usize() {
                    return Err(digest::InvalidLength);
                }
                Ok(Self::new_keyed(&[], output_size))
            }

            fn output_size(&self) -> usize {
                self.n
            }

            fn variable_result(self, buf: &mut [u8])
                                    -> Result<&[u8], digest::InvalidLength>
            {
                let n = buf.len();
                if n > self.output_size() {
                    Err(digest::InvalidLength)
                } else {
                    let res = self.finalize_with_flag(0);
                    copy_memory(&res[..n], buf);
                    Ok(buf)
                }
            }
        }

        impl Mac for $state {
            type OutputSize = $bytes;

            fn new(key: &[u8]) -> Self { Self::new_keyed(key, $bytes::to_usize()) }

            fn input(&mut self, data: &[u8]) { self.update(data); }

            fn result(self) -> MacResult<Self::OutputSize> {
                MacResult::new(self.finalize_with_flag(0))
            }
        }

    }
}

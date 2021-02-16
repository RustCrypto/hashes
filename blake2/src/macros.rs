macro_rules! blake2_impl {
    (
        $name:ident, $alg_name:expr, $word:ident, $vec:ident, $bytes:ident,
        $block_size:ident, $R1:expr, $R2:expr, $R3:expr, $R4:expr, $IV:expr,
        $vardoc:expr, $doc:expr,
    ) => {
        #[derive(Clone)]
        #[doc=$vardoc]
        pub struct $name {
            h: [$vec; 2],
            t: u64,
            // h0: [$vec; 2],
        }

        impl $name {
            #[inline(always)]
            fn iv0() -> $vec {
                $vec::new($IV[0], $IV[1], $IV[2], $IV[3])
            }
            #[inline(always)]
            fn iv1() -> $vec {
                $vec::new($IV[4], $IV[5], $IV[6], $IV[7])
            }

            /// Creates a new context with the full set of sequential-mode parameters.
            pub fn new_with_params(
                salt: &[u8],
                persona: &[u8],
                key_size: usize,
                output_size: usize,
            ) -> Self {
                assert!(key_size <= $bytes::to_usize());
                assert!(output_size <= $bytes::to_usize());

                // The number of bytes needed to express two words.
                let length = $bytes::to_usize() / 4;
                assert!(salt.len() <= length);
                assert!(persona.len() <= length);

                // Build a parameter block
                let mut p = [0 as $word; 8];
                p[0] = 0x0101_0000 ^ ((key_size as $word) << 8) ^ (output_size as $word);

                // salt is two words long
                if salt.len() < length {
                    let mut padded_salt =
                        GenericArray::<u8, <$bytes as Div<U4>>::Output>::default();
                    for i in 0..salt.len() {
                        padded_salt[i] = salt[i];
                    }
                    p[4] = $word::from_le_bytes(padded_salt[0..length / 2].try_into().unwrap());
                    p[5] = $word::from_le_bytes(
                        padded_salt[length / 2..padded_salt.len()]
                            .try_into()
                            .unwrap(),
                    );
                } else {
                    p[4] = $word::from_le_bytes(salt[0..salt.len() / 2].try_into().unwrap());
                    p[5] =
                        $word::from_le_bytes(salt[salt.len() / 2..salt.len()].try_into().unwrap());
                }

                // persona is also two words long
                if persona.len() < length {
                    let mut padded_persona =
                        GenericArray::<u8, <$bytes as Div<U4>>::Output>::default();
                    for i in 0..persona.len() {
                        padded_persona[i] = persona[i];
                    }
                    p[6] = $word::from_le_bytes(padded_persona[0..length / 2].try_into().unwrap());
                    p[7] = $word::from_le_bytes(
                        padded_persona[length / 2..padded_persona.len()]
                            .try_into()
                            .unwrap(),
                    );
                } else {
                    p[6] = $word::from_le_bytes(persona[0..length / 2].try_into().unwrap());
                    p[7] = $word::from_le_bytes(
                        persona[length / 2..persona.len()].try_into().unwrap(),
                    );
                }

                // if kk > 0 {
                //     copy(key, state.m.as_mut_bytes());
                //     state.t = 2 * $bytes::to_u64();
                // }

                // state.t0 = state.t;
                // state.m0 = state.m;

                $name {
                    h: [
                        Self::iv0() ^ $vec::new(p[0], p[1], p[2], p[3]),
                        Self::iv1() ^ $vec::new(p[4], p[5], p[6], p[7]),
                    ],
                    t: 0,
                }
            }

            fn finalize_with_flag(
                &mut self,
                final_block: &GenericArray<u8, $block_size>,
                flag: $word,
            ) -> GenericArray<u8, $bytes> {
                self.compress(final_block, !0, flag);
                let buf = [self.h[0].to_le(), self.h[1].to_le()];
                GenericArray::clone_from_slice(buf.as_bytes())
            }

            fn compress(&mut self, block: &GenericArray<u8, $block_size>, f0: $word, f1: $word) {
                use $crate::consts::SIGMA;

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
                    quarter_round(v, $R1, $R2, $vec::gather(m, s[0], s[2], s[4], s[6]));
                    quarter_round(v, $R3, $R4, $vec::gather(m, s[1], s[3], s[5], s[7]));

                    shuffle(v);
                    quarter_round(v, $R1, $R2, $vec::gather(m, s[8], s[10], s[12], s[14]));
                    quarter_round(v, $R3, $R4, $vec::gather(m, s[9], s[11], s[13], s[15]));
                    unshuffle(v);
                }

                let mut m: [$word; 16] = Default::default();
                let n = core::mem::size_of::<$word>();
                for (v, chunk) in m.iter_mut().zip(block.chunks_exact(n)) {
                    *v = $word::from_le_bytes(chunk.try_into().unwrap());
                }
                let h = &mut self.h;

                let t0 = self.t as $word;
                let t1 = match $bytes::to_u8() {
                    64 => 0,
                    32 => (self.t >> 32) as $word,
                    _ => unreachable!(),
                };

                let mut v = [
                    h[0],
                    h[1],
                    Self::iv0(),
                    Self::iv1() ^ $vec::new(t0, t1, f0, f1),
                ];

                round(&mut v, &m, &SIGMA[0]);
                round(&mut v, &m, &SIGMA[1]);
                round(&mut v, &m, &SIGMA[2]);
                round(&mut v, &m, &SIGMA[3]);
                round(&mut v, &m, &SIGMA[4]);
                round(&mut v, &m, &SIGMA[5]);
                round(&mut v, &m, &SIGMA[6]);
                round(&mut v, &m, &SIGMA[7]);
                round(&mut v, &m, &SIGMA[8]);
                round(&mut v, &m, &SIGMA[9]);
                if $bytes::to_u8() == 64 {
                    round(&mut v, &m, &SIGMA[0]);
                    round(&mut v, &m, &SIGMA[1]);
                }

                h[0] = h[0] ^ (v[0] ^ v[2]);
                h[1] = h[1] ^ (v[1] ^ v[3]);
            }
        }

        impl UpdateCore for $name {
            type BlockSize = $block_size;
            type Buffer = LazyBlockBuffer<Self::BlockSize>;

            fn update_blocks(&mut self, blocks: &[GenericArray<u8, $block_size>]) {
                for block in blocks {
                    self.t += block.len() as u64;
                    self.compress(block, 0, 0);
                }
            }
        }

        // impl FromKey for $name {
        //     type KeySize = $bytes;

        //     fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        //         Self::with_params(key, &[], &[], output_size)
        //     }

        //     fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        //         Self::with_params(key, &[], &[], output_size)
        //     }
        // }

        impl VariableOutputCore for $name {
            type MaxOutputSize = $bytes;

            #[inline]
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size > Self::MaxOutputSize::USIZE {
                    return Err(InvalidOutputSize);
                }
                Ok(Self::new_with_params(&[], &[], 0, output_size))
            }

            #[inline]
            fn finalize_variable_core(
                &mut self,
                buffer: &mut LazyBlockBuffer<Self::BlockSize>,
                output_size: usize,
                f: impl FnOnce(&[u8]),
            ) {
                self.t += buffer.get_pos() as u64;
                let block = buffer.pad_zeros();
                let res = self.finalize_with_flag(block, 0);
                f(&res[..output_size]);
            }
        }

        // impl Reset for $name {
        //     fn reset(&mut self) {
        //         self.t = self.t0;
        //         self.m = self.m0;
        //         self.h = self.h0;
        //     }
        // }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }
    };
}

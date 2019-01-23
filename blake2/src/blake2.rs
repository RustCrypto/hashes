macro_rules! blake2_compressor_impl {
    (
        $compressor:ident, $builder:ident, $word:ident, $vec:ident, $bytes:ident,
        $R1:expr, $R2:expr, $R3:expr, $R4:expr, $IV:expr,
        $XofLen:ident, $reserved_len:expr, $salt_len:expr,
    ) => {

        use $crate::as_bytes::AsBytes;
        use $crate::simd::{Vector4, $vec};

        use byte_tools::copy;
        use core::{mem, u8, u32};
        use digest::generic_array::GenericArray;
        use digest::generic_array::typenum::Unsigned;

        #[derive(Clone, Copy)]
        #[repr(packed)]
        #[allow(unused)]
        pub struct $builder {
            digest_len: u8,
            key_len: u8,
            fanout: u8,
            depth: u8,
            leaf_len: u32,
            node_offs: u32,
            xof_len: $XofLen,
            node_depth: u8,
            inner_len: u8,
            reserved: [u8; $reserved_len],
            salt: [u8; $salt_len],
            personal: [u8; $salt_len],
        }

        impl $builder {
            pub fn new() -> Self {
                Self {
                    digest_len: 0,
                    key_len: 0,
                    fanout: 1,
                    depth: 1,
                    leaf_len: 0,
                    node_offs: 0,
                    xof_len: 0,
                    node_depth: 0,
                    inner_len: 0,
                    reserved: Default::default(),
                    salt: Default::default(),
                    personal: Default::default(),
                }
            }

            pub fn out(&mut self, out: usize) {
                assert!(out <= usize::from(u8::MAX));
                self.digest_len = out as u8;
            }

            pub fn key(&mut self, kk: usize) {
                assert!(kk as usize <= $bytes::to_usize());
                self.key_len = kk as u8;
            }

            pub fn fanout(&mut self, fanout: u8) {
                self.fanout = fanout;
            }

            pub fn depth(&mut self, depth: u8) {
                self.depth = depth;
            }

            pub fn node_depth(&mut self, node_depth: u8) {
                self.node_depth = node_depth;
            }

            pub fn node_offset(&mut self, node_offs: usize) {
                assert!(node_offs <= u32::MAX as usize);
                assert!(node_offs as u32 <= u32::MAX);
                self.node_offs = u32::to_le(node_offs as u32);
            }

            pub fn inner_length(&mut self, inner_len: u8) {
                self.inner_len = inner_len;
            }

            pub fn build(&self) -> $compressor {
                assert!(self.digest_len > 0);
                // All fields of both types are Copy.
                // Field endianness is handled at field-setting time.
                let h0: [$vec; 2] = unsafe { mem::transmute(*self) };
                $compressor {
                    h: [iv0() ^ h0[0].to_le(), iv1() ^ h0[1].to_le()],
                }
            }
        }

        #[inline(always)]
        fn iv0() -> $vec { $vec::new($IV[0], $IV[1], $IV[2], $IV[3]) }
        #[inline(always)]
        fn iv1() -> $vec { $vec::new($IV[4], $IV[5], $IV[6], $IV[7]) }

        #[derive(Clone)]
        pub struct $compressor {
            h: [$vec; 2],
        }

        impl Default for $compressor {
            fn default() -> Self {
                Self {
                    h: [$vec::new(0, 0, 0, 0), $vec::new(0, 0, 0, 0)]
                }
            }
        }

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

        impl $compressor {
            pub fn with_parameter_block(p: &[$word; 8]) -> Self {
                let h0 = [
                    iv0() ^ $vec::new(p[0], p[1], p[2], p[3]),
                    iv1() ^ $vec::new(p[4], p[5], p[6], p[7]),
                ];
                Self {
                    h: h0,
                }
            }

            pub fn compress(&mut self, m: &[$word; 16], f0: $word, f1: $word, t: u64) {
                use $crate::consts::SIGMA;

                let h = &mut self.h;

                let t0 = t as $word;
                let t1 = match $bytes::to_u8() {
                    64 => 0,
                    32 => (t >> 32) as $word,
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

            pub fn finalize(&mut self, out: &mut GenericArray<u8, $bytes>, m: &[$word; 16], f1: $word, t: u64) {
                self.compress(m, !0, f1, t);
                let buf = [self.h[0].to_le(), self.h[1].to_le()];
                copy(buf.as_bytes(), out);
            }

            pub fn finalize_into_slice(&mut self, out: &mut [u8], m: &[$word; 16], f1: $word, t: u64) {
                self.compress(m, !0, f1, t);
                let buf = [self.h[0].to_le(), self.h[1].to_le()];
                out.copy_from_slice(buf.as_bytes());
            }

            pub fn builder() -> $builder {
                $builder::new()
            }
        }
    }
}

macro_rules! blake2_impl {
    (
        $state:ident, $fix_state:ident, $compressor:ident, $word:ident, $bytes:ident,
        $vardoc:expr, $doc:expr,
    ) => {

        use $crate::as_bytes::AsBytes;

        use digest::{Input, BlockInput, FixedOutput, VariableOutput, Reset};
        use digest::InvalidOutputSize;
        use digest::generic_array::GenericArray;
        use digest::generic_array::typenum::Unsigned;
        use core::cmp;
        use byte_tools::{copy, zero};
        use crypto_mac::{Mac, MacResult, InvalidKeyLength};

        type Output = GenericArray<u8, $bytes>;

        #[derive(Clone)]
        #[doc=$vardoc]
        pub struct $state {
            n: usize,
            h: $compressor,
            m: [$word; 16],
            h0: $compressor,
            m0: [$word; 16],
            t: u64,
            t0: u64,
        }

        impl $state {
            /// Creates a new hashing context with a key.
            ///
            /// **WARNING!** If you plan to use it for variable output MAC, then
            /// make sure to compare codes in constant time! It can be done
            /// for example by using `subtle` crate.
            pub fn new_keyed(key: &[u8], output_size: usize) -> Self {
                let mut h0 = $compressor::builder();
                h0.key(key.len());
                h0.out(output_size);
                let h0 = h0.build();
                let mut m = [0; 16];
                let mut t = 0;
                if !key.is_empty() {
                    copy(key, m.as_mut_bytes());
                    t = 2 * $bytes::to_u64();
                }
                $state {
                    m,
                    h: h0.clone(),
                    t,
                    n: output_size,

                    t0: t,
                    m0: m,
                    h0: h0,
                }
            }

            #[doc(hidden)]
            pub fn with_parameter_block(p: &[$word; 8]) -> Self {
                let nn = p[0] as u8 as usize;
                let kk = (p[0] >> 8) as u8 as usize;
                assert!(nn >= 1 && nn <= $bytes::to_usize());
                assert!(kk <= $bytes::to_usize());
                let h0 = $compressor::with_parameter_block(p);
                $state {
                    m: [0; 16],
                    h: h0.clone(),
                    t: 0,
                    n: nn,

                    t0: 0,
                    m0: [0; 16],
                    h0: h0,
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

                    copy(part, &mut self.m.as_mut_bytes()[off..]);
                    self.t = self.t.checked_add(part.len() as u64)
                        .expect("hash data length overflow");
                }

                for part in rest.chunks(block) {
                    self.h.compress(&self.m, 0, 0, self.t);

                    copy(part, &mut self.m.as_mut_bytes());
                    self.t = self.t.checked_add(part.len() as u64)
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
                let mut out = GenericArray::default();
                self.h.finalize(&mut out, &self.m, f1, self.t);
                out
            }
        }

        impl Default for $state {
            fn default() -> Self { Self::new_keyed(&[], $bytes::to_usize()) }
        }

        impl BlockInput for $state {
            type BlockSize = $bytes;
        }

        impl Input for $state {
            fn input<B: AsRef<[u8]>>(&mut self, data: B) {
                self.update(data.as_ref());
            }
        }

        impl VariableOutput for $state {
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size == 0 || output_size > $bytes::to_usize() {
                    return Err(InvalidOutputSize);
                }
                Ok(Self::new_keyed(&[], output_size))
            }

            fn output_size(&self) -> usize {
                self.n
            }

            fn variable_result<F: FnOnce(&[u8])>(self, f: F) {
                let n = self.n;
                let res = self.finalize_with_flag(0);
                f(&res[..n]);
            }
        }

        impl  Reset for $state {
            fn reset(&mut self) {
                self.t = self.t0;
                self.m = self.m0;
                self.h = self.h0.clone();
            }
        }

        impl_opaque_debug!($state);
        impl_write!($state);


        #[derive(Clone)]
        #[doc=$doc]
        pub struct $fix_state {
            state: $state,
        }

        impl Default for $fix_state {
            fn default() -> Self {
                let state = $state::new_keyed(&[], $bytes::to_usize());
                Self { state }
            }
        }

        impl BlockInput for $fix_state {
            type BlockSize = $bytes;
        }

        impl Input for $fix_state {
            fn input<B: AsRef<[u8]>>(&mut self, data: B) {
                self.state.update(data.as_ref());
            }
        }

        impl FixedOutput for $fix_state {
            type OutputSize = $bytes;

            fn fixed_result(self) -> Output {
                self.state.finalize_with_flag(0)
            }
        }

        impl  Reset for $fix_state {
            fn reset(&mut self) {
                self.state.reset()
            }
        }

        impl Mac for $fix_state {
            type OutputSize = $bytes;
            type KeySize = $bytes;

            fn new(key: &GenericArray<u8, $bytes>) -> Self {
                let state = $state::new_keyed(key, $bytes::to_usize());
                Self { state }
            }

            fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                if key.len() > $bytes::to_usize() {
                    Err(InvalidKeyLength)
                } else {
                    let state = $state::new_keyed(key, $bytes::to_usize());
                    Ok(Self { state })
                }
            }

            fn input(&mut self, data: &[u8]) { self.state.update(data); }

            fn reset(&mut self) {
                <Self as Reset>::reset(self)
            }

            fn result(self) -> MacResult<Self::OutputSize> {
                MacResult::new(self.state.finalize_with_flag(0))
            }
        }

        impl_opaque_debug!($fix_state);
        impl_write!($fix_state);
    }
}

macro_rules! blake2_p_impl {
    (
        $state:ident, $fix_state:ident, $compressor:ident, $builder:ident, $word:ident, $bytes:ident, $fanout:expr,
        $vardoc:expr, $doc:expr,
    ) => {

        use $crate::as_bytes::AsBytes;

        use digest::{Input, BlockInput, FixedOutput, VariableOutput, Reset};
        use digest::InvalidOutputSize;
        use digest::generic_array::GenericArray;
        use digest::generic_array::typenum::Unsigned;
        use core::cmp;
        use byte_tools::{copy, zero};
        use crypto_mac::{Mac, MacResult, InvalidKeyLength};

        type Output = GenericArray<u8, $bytes>;

        #[derive(Clone)]
        #[doc=$vardoc]
        pub struct $state {
            n: usize,
            m0: [$word; 16],
            t0: u64,
            h0: $builder,
            h: [$compressor; $fanout],
            m: [[$word; 16]; $fanout],
            t: u64,
        }

        impl $state {
            /// Creates a new hashing context with a key.
            ///
            /// **WARNING!** If you plan to use it for variable output MAC, then
            /// make sure to compare codes in constant time! It can be done
            /// for example by using `subtle` crate.
            pub fn new_keyed(key: &[u8], output_size: usize) -> Self {
                let mut h0 = $builder::new();
                h0.key(key.len());
                h0.out(output_size);
                h0.fanout($fanout);
                h0.depth(2);
                h0.inner_length($bytes::to_u8());
                let mut m0 = [0; 16];
                let mut t0 = 0;
                if !key.is_empty() {
                    copy(key, m0.as_mut_bytes());
                    t0 = 2 * $bytes::to_u64() * $fanout;
                }
                let mut state = $state {
                    n: output_size,
                    h0,
                    t0,
                    m0,
                    // everything else set up by reset()
                    h: Default::default(),
                    m: Default::default(),
                    t: Default::default(),
                };
                state.reset();
                state
            }

            /// Updates the hashing context with more data.
            fn update(&mut self, mut data: &[u8]) {
                const BLOCK: usize = 2 * $bytes::USIZE;
                const RING: usize = BLOCK * $fanout;

                if self.t < RING as u64 {
                    // initial ring fill
                    let (d0, d1) = data.split_at(cmp::min(data.len(), RING - self.t as usize));
                    self.m.as_mut_bytes()[self.t as usize..self.t as usize + d0.len()].copy_from_slice(d0);
                    self.t += d0.len() as u64;
                    data = d1;
                } else if self.t as usize % BLOCK != 0 {
                    // complete partial block
                    let (d0, d1) = data.split_at(cmp::min(data.len(), BLOCK - self.t as usize % BLOCK));
                    let ri = self.t as usize % RING;
                    self.m.as_mut_bytes()[ri..ri + d0.len()].copy_from_slice(d0);
                    self.t += d0.len() as u64;
                    data = d1;
                }

                // if there's data remaining, the ring is full of whole blocks
                for b in data.chunks(BLOCK) {
                    let i = self.t as usize / BLOCK % $fanout;
                    self.h[i].compress(&mut self.m[i], 0, 0, self.t / RING as u64 * BLOCK as u64);
                    self.m[i].as_mut_bytes()[..b.len()].copy_from_slice(b);
                    self.t += b.len() as u64;
                }
            }

            fn finalize(mut self) -> Output {
                const BLOCK: usize = 2 * $bytes::USIZE;
                const RING: usize = BLOCK * $fanout;

                self.h0.node_offset(0);
                self.h0.node_depth(1);
                let mut root = self.h0.build();

                let mut ri = self.t as usize % RING;
                let trb = self.t / RING as u64 * BLOCK as u64;
                if ri % BLOCK != 0 {
                    let ni = ((self.t as usize & !(BLOCK - 1)) + BLOCK) % RING;
                    zero(&mut self.m.as_mut_bytes()[ri..ni]);
                }
                let mut inter = [0; 16];
                for i in 0..$fanout {
                    if i != 0 && i & 1 == 0 {
                        root.compress(&inter, 0, 0, i as u64 * $bytes::to_u64());
                    }
                    let len = cmp::min(ri, BLOCK);
                    ri -= len;
                    let f1 = if i == $fanout - 1 { !0 } else { 0 };
                    let ix0 = (i & 1) * $bytes::to_usize();
                    let ix1 = ((i & 1) + 1) * $bytes::to_usize();
                    self.h[i].finalize_into_slice(&mut inter.as_mut_bytes()[ix0..ix1], &self.m[i], f1, trb + len as u64);
                }
                let mut out = GenericArray::default();
                root.finalize(&mut out, &inter, !0, $fanout * $bytes::to_u64());
                out
            }
        }

        impl Default for $state {
            fn default() -> Self { Self::new_keyed(&[], $bytes::to_usize()) }
        }

        impl BlockInput for $state {
            type BlockSize = $bytes;
        }

        impl Input for $state {
            fn input<B: AsRef<[u8]>>(&mut self, data: B) {
                self.update(data.as_ref());
            }
        }

        impl VariableOutput for $state {
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size == 0 || output_size > $bytes::to_usize() {
                    return Err(InvalidOutputSize);
                }
                Ok(Self::new_keyed(&[], output_size))
            }

            fn output_size(&self) -> usize {
                self.n
            }

            fn variable_result<F: FnOnce(&[u8])>(self, f: F) {
                let n = self.n;
                let res = self.finalize();
                f(&res[..n]);
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.h0.node_depth(0);
                for (i, h) in self.h.iter_mut().enumerate() {
                    self.h0.node_offset(i);
                    *h = self.h0.build();
                }

                for m in self.m.iter_mut() {
                    m.copy_from_slice(&self.m0);
                }

                self.t = self.t0;
            }
        }

        impl_opaque_debug!($state);
        impl_write!($state);


        #[derive(Clone)]
        #[doc=$doc]
        pub struct $fix_state {
            state: $state,
        }

        impl Default for $fix_state {
            fn default() -> Self {
                let state = $state::new_keyed(&[], $bytes::to_usize());
                Self { state }
            }
        }

        impl BlockInput for $fix_state {
            type BlockSize = $bytes;
        }

        impl Input for $fix_state {
            fn input<B: AsRef<[u8]>>(&mut self, data: B) {
                self.state.update(data.as_ref());
            }
        }

        impl FixedOutput for $fix_state {
            type OutputSize = $bytes;

            fn fixed_result(self) -> Output {
                self.state.finalize()
            }
        }

        impl  Reset for $fix_state {
            fn reset(&mut self) {
                self.state.reset()
            }
        }

        impl Mac for $fix_state {
            type OutputSize = $bytes;
            type KeySize = $bytes;

            fn new(key: &GenericArray<u8, $bytes>) -> Self {
                let state = $state::new_keyed(key, $bytes::to_usize());
                Self { state }
            }

            fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                if key.len() > $bytes::to_usize() {
                    Err(InvalidKeyLength)
                } else {
                    let state = $state::new_keyed(key, $bytes::to_usize());
                    Ok(Self { state })
                }
            }

            fn input(&mut self, data: &[u8]) { self.state.update(data); }

            fn reset(&mut self) {
                <Self as Reset>::reset(self)
            }

            fn result(self) -> MacResult<Self::OutputSize> {
                MacResult::new(self.state.finalize())
            }
        }

        impl_opaque_debug!($fix_state);
        impl_write!($fix_state);
    }
}

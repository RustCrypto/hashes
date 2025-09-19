macro_rules! blake2_impl {
    (
        $name:ident, $alg_name:expr, $word:ident, $vec:ident, $bytes:ident,
        $block_size:ident, $R1:expr, $R2:expr, $R3:expr, $R4:expr, $IV:expr,
        $vardoc:expr, $doc:expr,
    ) => {
        #[derive(Clone)]
        #[doc=$vardoc]
        pub struct $name {
            /// Blake2 state vector (8 words total, stored as 2 SIMD vectors).
            pub(crate) h: [$vec; 2],
            /// Total number of bytes processed so far.
            pub t: u64,
            #[cfg(feature = "reset")]
            /// Initial state vector for reset functionality.
            pub(crate) h0: [$vec; 2],
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
                    let mut padded_salt = Array::<u8, <$bytes as Div<U4>>::Output>::default();
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
                    let mut padded_persona = Array::<u8, <$bytes as Div<U4>>::Output>::default();
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

                let h = [
                    Self::iv0() ^ $vec::new(p[0], p[1], p[2], p[3]),
                    Self::iv1() ^ $vec::new(p[4], p[5], p[6], p[7]),
                ];
                $name {
                    #[cfg(feature = "reset")]
                    h0: h.clone(),
                    h,
                    t: 0,
                }
            }

            fn finalize_with_flag(
                &mut self,
                final_block: &Array<u8, $block_size>,
                flag: $word,
                out: &mut Output<Self>,
            ) {
                self.compress(final_block, !0, flag);
                let buf = [self.h[0].to_le(), self.h[1].to_le()];
                out.copy_from_slice(buf.as_bytes())
            }

            fn compress(&mut self, block: &Block<Self>, f0: $word, f1: $word) {
                use $crate::consts::SIGMA;

                #[cfg_attr(not(feature = "size_opt"), inline(always))]
                fn quarter_round(v: &mut [$vec; 4], rd: u32, rb: u32, m: $vec) {
                    v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
                    v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
                    v[2] = v[2].wrapping_add(v[3]);
                    v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
                }

                #[cfg_attr(not(feature = "size_opt"), inline(always))]
                fn shuffle(v: &mut [$vec; 4]) {
                    v[1] = v[1].shuffle_left_1();
                    v[2] = v[2].shuffle_left_2();
                    v[3] = v[3].shuffle_left_3();
                }

                #[cfg_attr(not(feature = "size_opt"), inline(always))]
                fn unshuffle(v: &mut [$vec; 4]) {
                    v[1] = v[1].shuffle_right_1();
                    v[2] = v[2].shuffle_right_2();
                    v[3] = v[3].shuffle_right_3();
                }

                #[cfg_attr(not(feature = "size_opt"), inline(always))]
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
                    *v = $word::from_ne_bytes(chunk.try_into().unwrap());
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

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        impl BufferKindUser for $name {
            type BufferKind = Lazy;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.t += block.len() as u64;
                    self.compress(block, 0, 0);
                }
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = $bytes;
        }

        impl VariableOutputCore for $name {
            const TRUNC_SIDE: TruncSide = TruncSide::Left;

            #[inline]
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size > Self::OutputSize::USIZE {
                    return Err(InvalidOutputSize);
                }
                Ok(Self::new_with_params(&[], &[], 0, output_size))
            }

            #[inline]
            fn finalize_variable_core(
                &mut self,
                buffer: &mut Buffer<Self>,
                out: &mut Output<Self>,
            ) {
                self.t += buffer.get_pos() as u64;
                let block = buffer.pad_with_zeros();
                self.finalize_with_flag(&block, 0, out);
            }
        }

        #[cfg(feature = "reset")]
        impl Reset for $name {
            fn reset(&mut self) {
                self.h = self.h0;
                self.t = 0;
            }
        }

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

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    self.h.zeroize();
                    self.t.zeroize();
                }
            }
        }

        impl VariableOutputCoreCustomized for $name {
            #[inline]
            fn new_customized(customization: &[u8], output_size: usize) -> Self {
                Self::new_with_params(&[], customization, 0, output_size)
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}
    };
}

macro_rules! blake2_mac_impl {
    (
        $name:ident, $hash:ty, $max_size:ty, $doc:expr
    ) => {
        #[derive(Clone)]
        #[doc=$doc]
        pub struct $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            core: $hash,
            buffer: LazyBuffer<<$hash as BlockSizeUser>::BlockSize>,
            #[cfg(feature = "reset")]
            key_block: Option<Key<Self>>,
            _out: PhantomData<OutSize>,
        }

        impl<OutSize> $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            /// Create new instance using provided key, salt, and persona.
            ///
            /// Setting key to `None` indicates unkeyed usage.
            ///
            /// # Errors
            ///
            /// If key is `Some`, then its length should not be zero or bigger
            /// than the block size. The salt and persona length should not be
            /// bigger than quarter of block size. If any of those conditions is
            /// false the method will return an error.
            #[inline]
            pub fn new_with_salt_and_personal(
                key: Option<&[u8]>,
                salt: &[u8],
                persona: &[u8],
            ) -> Result<Self, InvalidLength> {
                let kl = key.map_or(0, |k| k.len());
                let bs = <$hash as BlockSizeUser>::BlockSize::USIZE;
                let qbs = bs / 4;
                if key.is_some() && kl == 0 || kl > bs || salt.len() > qbs || persona.len() > qbs {
                    return Err(InvalidLength);
                }
                let buffer = if let Some(k) = key {
                    let mut padded_key = Block::<$hash>::default();
                    padded_key[..kl].copy_from_slice(k);
                    LazyBuffer::new(&padded_key)
                } else {
                    LazyBuffer::default()
                };
                Ok(Self {
                    core: <$hash>::new_with_params(salt, persona, kl, OutSize::USIZE),
                    buffer,
                    #[cfg(feature = "reset")]
                    key_block: key.map(|k| {
                        let mut t = Key::<Self>::default();
                        t[..kl].copy_from_slice(k);
                        t
                    }),
                    _out: PhantomData,
                })
            }
        }

        impl<OutSize> KeySizeUser for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            type KeySize = $max_size;
        }

        impl<OutSize> KeyInit for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                Self::new_from_slice(key).expect("Key has correct length")
            }

            #[inline]
            fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
                let kl = key.len();
                if kl > <Self as KeySizeUser>::KeySize::USIZE {
                    return Err(InvalidLength);
                }
                let mut padded_key = Block::<$hash>::default();
                padded_key[..kl].copy_from_slice(key);
                Ok(Self {
                    core: <$hash>::new_with_params(&[], &[], key.len(), OutSize::USIZE),
                    buffer: LazyBuffer::new(&padded_key),
                    #[cfg(feature = "reset")]
                    key_block: {
                        let mut t = Key::<Self>::default();
                        t[..kl].copy_from_slice(key);
                        Some(t)
                    },
                    _out: PhantomData,
                })
            }
        }

        impl<OutSize> Update for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            #[inline]
            fn update(&mut self, input: &[u8]) {
                let Self { core, buffer, .. } = self;
                buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
            }
        }

        impl<OutSize> OutputSizeUser for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            type OutputSize = OutSize;
        }

        impl<OutSize> FixedOutput for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            #[inline]
            fn finalize_into(mut self, out: &mut Output<Self>) {
                let Self { core, buffer, .. } = &mut self;
                let mut full_res = Default::default();
                core.finalize_variable_core(buffer, &mut full_res);
                out.copy_from_slice(&full_res[..OutSize::USIZE]);
            }
        }

        #[cfg(feature = "reset")]
        impl<OutSize> Reset for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            fn reset(&mut self) {
                self.core.reset();
                self.buffer = if let Some(k) = self.key_block {
                    let kl = k.len();
                    let mut padded_key = Block::<$hash>::default();
                    padded_key[..kl].copy_from_slice(&k);
                    LazyBuffer::new(&padded_key)
                } else {
                    LazyBuffer::default()
                }
            }
        }

        #[cfg(feature = "reset")]
        impl<OutSize> FixedOutputReset for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                let Self { core, buffer, .. } = self;
                let mut full_res = Default::default();
                core.finalize_variable_core(buffer, &mut full_res);
                out.copy_from_slice(&full_res[..OutSize::USIZE]);
                self.reset();
            }
        }

        impl<OutSize> MacMarker for $name<OutSize> where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>
        {
        }

        impl<OutSize> fmt::Debug for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{} {{ ... }}", stringify!($name), OutSize::USIZE)
            }
        }

        impl<OutSize> Drop for $name<OutSize>
        where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>,
        {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    // `self.core` zeroized by its `Drop` impl
                    self.buffer.zeroize();
                    #[cfg(feature = "reset")]
                    if let Some(mut key_block) = self.key_block {
                        key_block.zeroize();
                    }
                }
            }
        }
        #[cfg(feature = "zeroize")]
        impl<OutSize> ZeroizeOnDrop for $name<OutSize> where
            OutSize: ArraySize + IsLessOrEqual<$max_size, Output = True>
        {
        }
    };
}

#[cfg(feature = "blake2x")]
macro_rules! blake2x_impl {
    (
        $core_name:ident, $reader_name:ident, $hasher_name:ident, $reader_type:ident,
        $alg_name:expr, $word:ident, $vec:ident, $bytes:ident, $hash_size:expr,
        $block_size:ident, $reader_block_size:ident, $xof_len_type:ident, $IV:expr,
        $vardoc:expr, $base_core:path,
    ) => {
        /// Blake2X XOF core implementation.
        ///
        /// Implements the Blake2X extended output function which builds on top of Blake2b/Blake2s
        /// to provide variable-length output. The XOF length parameter is incorporated into the
        /// root hash computation to ensure different output lengths produce different results.
        #[derive(Clone)]
        pub struct $core_name {
            /// The root hasher for this variant of Blake2X.
            pub root_hasher: $base_core,
            /// The XOF length for this variant of Blake2X.
            xof_len: $xof_len_type,
        }

        impl $core_name {
            /// Create new core with specified output length.
            pub fn new(xof_len: $xof_len_type) -> Self {
                // Root hasher construction is delegated to new_blake2x_root_hasher for deduplication and correctness.
                $core_name {
                    root_hasher: Self::new_blake2x_root_hasher(xof_len),
                    xof_len,
                }
            }

            /// Create new core with specified output length and a key.
            pub fn new_with_key(key: &[u8], xof_len: $xof_len_type) -> Self {
                $core_name {
                    root_hasher: Self::new_blake2x_root_hasher_with_key(key, xof_len),
                    xof_len,
                }
            }

            /// Apply XOF length parameter adjustments to a Blake2 hasher state.
            ///
            /// The Blake2X specification requires the total output length (xof_len) to be
            /// incorporated into the parameter block of the root hash computation. This ensures
            /// that Blake2X(M, L1) and Blake2X(M, L2) produce different outputs when L1 ≠ L2.
            ///
            /// This helper function encapsulates the word-size specific logic for both
            /// Blake2b (64-bit) and Blake2s (32-bit) variants.
            fn xof_parameter_adjustment(hasher: &mut $base_core, xof_len: $xof_len_type) {
                let xof_param_vec = if core::mem::size_of::<$word>() == 8 {
                    // Blake2b: xof_length is a u32 in the high 32-bits of parameter word p[1]
                    let xof_param_val = ((xof_len as u64) << 32) as $word;
                    $vec::new(0 as $word, xof_param_val, 0 as $word, 0 as $word)

                } else {
                    // Blake2s: xof_digest_length is a u32 in parameter word p[3].
                    // We start with a standard Blake2s parameter block and then
                    // XOR in the xof_len to modify the h state corresponding to p[3].
                    let xof_param_val = xof_len as $word;
                    // The parameter p[3] is the 4th element of the first SIMD vector.
                    $vec::new(0, 0, 0, xof_param_val)
                };
                hasher.h[0] = hasher.h[0] ^ xof_param_vec;
                #[cfg(feature = "reset")]
                { hasher.h0[0] = hasher.h0[0] ^ xof_param_vec; }
            }

            /// Create Blake2 hasher specifically for Blake2X root hash computation.
            fn new_blake2x_root_hasher(xof_len: $xof_len_type) -> $base_core {
                let mut hasher = <$base_core>::new_with_params(&[], &[], 0, $hash_size);
                Self::xof_parameter_adjustment(&mut hasher, xof_len);
                hasher
            }

            /// Create Blake2 hasher for a keyed Blake2X root hash.
            ///
            /// This is similar to new_blake2x_root_hasher but includes the key length
            /// in the parameter block for proper keyed hashing support.
            fn new_blake2x_root_hasher_with_key(key: &[u8], xof_len: $xof_len_type) -> $base_core {
                let mut hasher = <$base_core>::new_with_params(&[], &[], key.len(), $hash_size);
                Self::xof_parameter_adjustment(&mut hasher, xof_len);
                hasher
            }
        }

        impl Default for $core_name {
            fn default() -> Self {
                Self::new(<$xof_len_type>::MAX) // Unknown size by default
            }
        }

        impl HashMarker for $core_name {}

        impl BlockSizeUser for $core_name {
            type BlockSize = $block_size;
        }

        impl BufferKindUser for $core_name {
            type BufferKind = Lazy;
        }

        impl UpdateCore for $core_name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                self.root_hasher.update_blocks(blocks);
            }
        }

        impl ExtendableOutputCore for $core_name {
            type ReaderCore = $reader_name;

            fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
                // Finalize the root hash H0
                let mut root_output = Output::<$base_core>::default();
                self.root_hasher.finalize_variable_core(buffer, &mut root_output);

                $reader_name::new(root_output.into(), self.xof_len)
            }
        }

        impl AlgorithmName for $core_name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl fmt::Debug for $core_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($core_name), " { ... }"))
            }
        }

        #[cfg(feature = "reset")]
        impl Reset for $core_name {
            fn reset(&mut self) {
                self.root_hasher.reset();
            }
        }

        impl SerializableState for $core_name {
            type SerializedStateSize = $bytes;

            fn serialize(&self) -> digest::crypto_common::hazmat::SerializedState<Self> {
                let mut state = digest::crypto_common::hazmat::SerializedState::<Self>::default();
                let len_bytes = core::mem::size_of::<$xof_len_type>();
                state[..len_bytes].copy_from_slice(&self.xof_len.to_le_bytes());
                state
            }

            fn deserialize(
                serialized_state: &digest::crypto_common::hazmat::SerializedState<Self>,
            ) -> Result<Self, digest::crypto_common::hazmat::DeserializeStateError> {
                let len_bytes = core::mem::size_of::<$xof_len_type>();
                let mut xof_len_bytes = [0u8; 8]; // Max size for either u16 or u32
                xof_len_bytes[..len_bytes].copy_from_slice(&serialized_state[..len_bytes]);
                let xof_len = <$xof_len_type>::from_le_bytes(
                    xof_len_bytes[..len_bytes].try_into().unwrap()
                );
                Ok(Self::new(xof_len))
            }
        }

        /// XOF reader core.
        #[derive(Clone)]
        pub struct $reader_name {
            root_hash: [u8; $hash_size],
            node_offset: u32,
            position: usize,
            remaining: $xof_len_type,
            total_xof_len: $xof_len_type,
        }

        impl $reader_name {
            fn new(root_hash: [u8; $hash_size], xof_len: $xof_len_type) -> Self {
                Self {
                    root_hash,
                    node_offset: 0,
                    position: 0,
                    remaining: xof_len,
                    total_xof_len: xof_len,
                }
            }
        }

        impl BlockSizeUser for $reader_name {
            type BlockSize = $reader_block_size;
        }


        impl $reader_name {
            /// Build expansion node parameter array for Blake2X.
            ///
            /// Creates a unified parameter word array that encodes the expansion node
            /// parameters according to the Blake2X specification. This handles the
            /// word-size differences between Blake2b and Blake2s variants.
            fn build_expansion_node_params(
                node_offset: u32,
                output_size: usize,
                total_xof_len: $xof_len_type
            ) -> [$word; 8] {
                let mut p = [0 as $word; 8];

                if core::mem::size_of::<$word>() == 4 {
                    // Blake2s (32-bit words)
                    // p[0]: digest_len | key_len (0) | fanout (0) | depth (0)
                    p[0] = output_size as $word;
                    // p[1]: leaf_length (should be hash_size for Blake2Xs per specification)
                    p[1] = $hash_size as $word;
                    // p[2]: node_offset (the block counter)
                    p[2] = node_offset as $word;
                    // p[3]: xof_len(u16) | node_depth(u8, 0) << 16 | inner_len(u8, hash_size) << 24
                    let xof_len = total_xof_len as $word;
                    let node_depth = 0 as $word;
                    let inner_len = $hash_size as $word;
                    p[3] = xof_len | (node_depth << 16) | (inner_len << 24);
                } else {
                    // Blake2b (64-bit words)

                    // p[0]: Contains bytes 0-7 with digest_length, key_length, fanout, depth, leaf_length
                    let digest_length = output_size as u64;
                    let key_length = 0u64; // No key for expansion nodes
                    let fanout = 0u64; // Unlimited fanout
                    let depth = 0u64; // Unlimited depth
                    let leaf_length = ($hash_size as u64) << 32;
                    p[0] = (digest_length | (key_length << 8) | (fanout << 16) | (depth << 24) | leaf_length) as $word;

                    // p[1]: Contains bytes 8-15 with node_offset (with XOF length in upper 32 bits)
                    // For Blake2b expansion nodes, we include the XOF length in the upper bits
                    let node_offset_full = ((total_xof_len as u64) << 32) + (node_offset as u64);
                    p[1] = node_offset_full as $word;

                    // p[2]: Contains bytes 16-23 with node_depth, inner_length
                    let node_depth = 0u64; // Leaf level
                    let inner_length = ($hash_size as u64) << 8;
                    p[2] = (node_depth | inner_length) as $word;

                    // p[3..7]: All zeros (already initialized)
                }

                p
            }

            /// Create hasher with expansion node parameter state.
            ///
            /// Initializes a Blake2 hasher with the given parameter array by XORing
            /// the initialization vector with the parameter block.
            fn create_hasher_with_params(p: &[$word; 8]) -> $base_core {
                // Initialize state h = IV ^ p
                let h = [
                    $vec::new($IV[0], $IV[1], $IV[2], $IV[3]) ^ $vec::new(p[0], p[1], p[2], p[3]),
                    $vec::new($IV[4], $IV[5], $IV[6], $IV[7]) ^ $vec::new(p[4], p[5], p[6], p[7]),
                ];

                // Create hasher with expansion node parameters
                let mut node = <$base_core>::new_with_params(&[], &[], 0, $hash_size);
                node.h = h;
                #[cfg(feature = "reset")]
                { node.h0 = h; }

                node
            }

            /// Blake2X expansion node function.
            ///
            /// Implements B2(node_offset, output_size, H0) from the Blake2X specification.
            /// Each expansion node computes Blake2(H0) with specific tree parameters that
            /// encode the node offset and output size.
            fn expand_node(h0: &[u8; $hash_size], node_offset: u32, output_size: usize, total_xof_len: $xof_len_type) -> [u8; $hash_size] {
                // Build expansion node parameter array
                let p = Self::build_expansion_node_params(node_offset, output_size, total_xof_len);

                // Create the node hasher with the parameter state
                let mut node_hasher = Self::create_hasher_with_params(&p);

                // The hashing logic is now unified for both Blake2b and Blake2s
                let mut buffer = LazyBuffer::default();
                buffer.digest_blocks(h0, |blocks| {
                    node_hasher.update_blocks(blocks);
                });

                // Finalize and return
                let mut output = [0u8; $hash_size];
                let mut var_output = Output::<$base_core>::default();
                node_hasher.finalize_variable_core(&mut buffer, &mut var_output);
                output[..output_size].copy_from_slice(&var_output[..output_size]);
                output
            }
        }

        impl XofReaderCore for $reader_name {
            fn read_block(&mut self) -> Block<Self> {
                let mut block = Block::<Self>::default();

                if self.remaining == 0 {
                    return block; // Return zeros if no more output needed
                }

                // Determine output size for this block
                let output_size = if self.remaining >= $hash_size as $xof_len_type {
                    $hash_size
                } else {
                    self.remaining as usize
                };

                // Blake2x expansion: Hash H0 with specific tree parameters for this node
                let node_output = Self::expand_node(&self.root_hash, self.node_offset, output_size, self.total_xof_len);

                // Copy output to block
                block[..output_size].copy_from_slice(&node_output[..output_size]);

                // Update state
                self.node_offset += 1;
                self.position += output_size;
                self.remaining -= output_size as $xof_len_type;

                block
            }
        }

        impl fmt::Debug for $reader_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($reader_name), " { ... }"))
            }
        }


        // Use buffer_xof macro to create the wrapper types
        digest::buffer_xof!(
            #[doc=$vardoc]
            pub struct $hasher_name($core_name);
            impl: Debug AlgorithmName Clone Default BlockSizeUser CoreProxy HashMarker Update;
            /// XOF reader.
            pub struct $reader_type($reader_name);
            impl: XofReaderTraits;
        );
    };
}

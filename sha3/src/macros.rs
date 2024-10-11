macro_rules! impl_sha3 {
    (
        $name:ident, $full_name:ident, $output_size:ident,
        $rate:ident, $pad:expr, $alg_name:expr $(,)?
    ) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name {
            state: Sha3State,
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.state.absorb_block(block)
                }
            }
        }

        impl FixedOutputCore for $name {
            #[inline]
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                let pos = buffer.get_pos();
                let mut block = buffer.pad_with_zeros();
                block[pos] = $pad;
                let n = block.len();
                block[n - 1] |= 0x80;

                self.state.absorb_block(&block);

                self.state.as_bytes(out);
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    state: Default::default(),
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
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
                    self.state.state.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}

        impl SerializableState for $name {
            type SerializedStateSize = U200;

            fn serialize(&self) -> SerializedState<Self> {
                let mut serialized_state = SerializedState::<Self>::default();

                for (val, chunk) in self
                    .state
                    .state
                    .iter()
                    .zip(serialized_state.chunks_exact_mut(8))
                {
                    chunk.copy_from_slice(&val.to_le_bytes());
                }

                serialized_state
            }

            fn deserialize(
                serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                use core::convert::TryInto;

                let mut state = Sha3State::default();
                for (val, chunk) in state.state.iter_mut().zip(serialized_state.chunks_exact(8)) {
                    *val = u64::from_le_bytes(chunk.try_into().unwrap());
                }

                Ok(Self { state })
            }
        }
    };
    (
        $name:ident, $full_name:ident, $output_size:ident,
        $rate:ident, $pad:expr, $alg_name:expr, $oid:literal $(,)?
    ) => {
        impl_sha3!($name, $full_name, $output_size, $rate, $pad, $alg_name);

        #[cfg(feature = "oid")]
        impl AssociatedOid for $name {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        }
    };
}

macro_rules! impl_shake {
    (
        $name:ident, $full_name:ident, $reader:ident, $reader_full:ident,
        $rate:ident, $pad:expr, $alg_name:expr $(,)?
    ) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name {
            state: Sha3State,
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.state.absorb_block(block)
                }
            }
        }

        impl ExtendableOutputCore for $name {
            type ReaderCore = $reader;

            #[inline]
            fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
                let pos = buffer.get_pos();
                let mut block = buffer.pad_with_zeros();
                block[pos] = $pad;
                let n = block.len();
                block[n - 1] |= 0x80;

                self.state.absorb_block(&block);
                $reader {
                    state: self.state.clone(),
                }
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    state: Default::default(),
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
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
                    self.state.state.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}

        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " reader state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $reader {
            state: Sha3State,
        }

        #[doc = $alg_name]
        #[doc = " reader state."]
        pub type $reader_full = XofReaderCoreWrapper<$reader>;

        impl BlockSizeUser for $reader {
            type BlockSize = $rate;
        }

        impl XofReaderCore for $reader {
            #[inline]
            fn read_block(&mut self) -> Block<Self> {
                let mut block = Block::<Self>::default();
                self.state.as_bytes(&mut block);
                self.state.permute();
                block
            }
        }

        impl Drop for $reader {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    self.state.state.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $reader {}
    };
    (
        $name:ident, $full_name:ident, $reader:ident, $reader_full:ident,
        $rate:ident, $pad:expr, $alg_name:expr, $oid:literal $(,)?
    ) => {
        impl_shake!(
            $name,
            $full_name,
            $reader,
            $reader_full,
            $rate,
            $pad,
            $alg_name
        );

        #[cfg(feature = "oid")]
        impl AssociatedOid for $name {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        }
    };
}

macro_rules! impl_turbo_shake {
    (
        $name:ident, $full_name:ident, $reader:ident, $reader_full:ident,
        $rate:ident, $alg_name:expr $(,)?
    ) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name {
            state: Sha3State<TURBO_SHAKE_ROUND_COUNT>,
            domain_separation: u8,
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;

        impl $name {
            /// Creates a new TurboSHAKE instance with the given domain separation.
            /// Note that the domain separation needs to be a byte with a value in
            /// the range [0x01, . . . , 0x7F]
            pub fn new(domain_separation: u8) -> Self {
                assert!((0x01..=0x7F).contains(&domain_separation));
                Self {
                    domain_separation,
                    state: Default::default(),
                }
            }
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.state.absorb_block(block)
                }
            }
        }

        impl ExtendableOutputCore for $name {
            type ReaderCore = $reader;

            #[inline]
            fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
                let pos = buffer.get_pos();
                let mut block = buffer.pad_with_zeros();
                block[pos] = self.domain_separation;
                let n = block.len();
                block[n - 1] |= 0x80;

                self.state.absorb_block(&block);
                $reader {
                    state: self.state.clone(),
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Self::new(self.domain_separation);
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
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
                    self.state.state.zeroize();
                    self.domain_separation.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}

        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " reader state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $reader {
            state: Sha3State<TURBO_SHAKE_ROUND_COUNT>,
        }

        #[doc = $alg_name]
        #[doc = " reader state."]
        pub type $reader_full = XofReaderCoreWrapper<$reader>;

        impl BlockSizeUser for $reader {
            type BlockSize = $rate;
        }

        impl XofReaderCore for $reader {
            #[inline]
            fn read_block(&mut self) -> Block<Self> {
                let mut block = Block::<Self>::default();
                self.state.as_bytes(&mut block);
                self.state.permute();
                block
            }
        }

        impl Drop for $reader {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    self.state.state.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $reader {}
    };
    (
        $name:ident, $full_name:ident, $reader:ident, $reader_full:ident,
        $rate:ident, $alg_name:expr, $oid:literal $(,)?
    ) => {
        impl_turbo_shake!($name, $full_name, $reader, $reader_full, $rate, $alg_name);

        #[cfg(feature = "oid")]
        impl AssociatedOid for $name {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        }
    };
}

macro_rules! impl_cshake {
    (
        $name:ident, $full_name:ident, $reader:ident, $reader_full:ident,
        $rate:ident, $shake_pad:expr, $cshake_pad:expr, $alg_name:expr,
    ) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name {
            state: Sha3State,
            #[cfg(feature = "reset")]
            initial_state: Sha3State,
            padding: u8,
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;

        impl $name {
            /// Creates a new CSHAKE instance with the given function name and customization.
            /// Note that the function name is intended for use by NIST and should only be set to
            /// values defined by NIST. You probably don't need to use this function.
            pub fn new_with_function_name(function_name: &[u8], customization: &[u8]) -> Self {
                let mut state = Sha3State::default();
                if function_name.is_empty() && customization.is_empty() {
                    return Self {
                        padding: $shake_pad,
                        state: state.clone(),
                        #[cfg(feature = "reset")]
                        initial_state: state,
                    };
                }

                let mut buffer = Buffer::<Self>::default();
                let mut b = [0u8; 9];
                buffer.digest_blocks(left_encode($rate::to_u64(), &mut b), |blocks| {
                    for block in blocks {
                        state.absorb_block(block);
                    }
                });
                buffer.digest_blocks(
                    left_encode((function_name.len() * 8) as u64, &mut b),
                    |blocks| {
                        for block in blocks {
                            state.absorb_block(block);
                        }
                    },
                );
                buffer.digest_blocks(function_name, |blocks| {
                    for block in blocks {
                        state.absorb_block(block);
                    }
                });
                buffer.digest_blocks(
                    left_encode((customization.len() * 8) as u64, &mut b),
                    |blocks| {
                        for block in blocks {
                            state.absorb_block(block);
                        }
                    },
                );
                buffer.digest_blocks(customization, |blocks| {
                    for block in blocks {
                        state.absorb_block(&block);
                    }
                });
                state.absorb_block(&buffer.pad_with_zeros());

                Self {
                    padding: $cshake_pad,
                    state: state.clone(),
                    #[cfg(feature = "reset")]
                    initial_state: state,
                }
            }
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.state.absorb_block(block)
                }
            }
        }

        impl ExtendableOutputCore for $name {
            type ReaderCore = $reader;

            #[inline]
            fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
                let pos = buffer.get_pos();
                let mut block = buffer.pad_with_zeros();
                block[pos] = self.padding;
                let n = block.len();
                block[n - 1] |= 0x80;

                self.state.absorb_block(&block);
                $reader {
                    state: self.state.clone(),
                }
            }
        }

        #[cfg(feature = "reset")]
        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.state = self.initial_state.clone();
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
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
                    self.state.state.zeroize();
                    self.padding.zeroize();
                    #[cfg(feature = "reset")]
                    self.initial_state.state.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}

        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " reader state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $reader {
            state: Sha3State,
        }

        #[doc = $alg_name]
        #[doc = " reader state."]
        pub type $reader_full = XofReaderCoreWrapper<$reader>;

        impl BlockSizeUser for $reader {
            type BlockSize = $rate;
        }

        impl XofReaderCore for $reader {
            #[inline]
            fn read_block(&mut self) -> Block<Self> {
                let mut block = Block::<Self>::default();
                self.state.as_bytes(&mut block);
                self.state.permute();
                block
            }
        }

        impl Drop for $reader {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    self.state.state.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $reader {}

        impl CustomizedInit for $name {
            #[inline]
            fn new_customized(customization: &[u8]) -> Self {
                Self::new_with_function_name(&[], customization)
            }
        }
    };
}

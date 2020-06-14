macro_rules! blake2_impl {
    (
        $state:ident, $fix_state:ident, $upstream_state:ty,
        $upstream_params:ty, $block_bytes_typenum:ty, $key_bytes_typenum:ty,
        $out_bytes_typenum:ty, $vardoc:expr, $doc:expr,
    ) => {

        use digest::{Update, BlockInput, FixedOutputDirty, VariableOutputDirty, Reset};
        use digest::InvalidOutputSize;
        use digest::generic_array::GenericArray;
        use digest::generic_array::typenum::Unsigned;
        use crypto_mac::{InvalidKeyLength, Mac, NewMac};

        type Output = GenericArray<u8, $out_bytes_typenum>;

        #[derive(Clone)]
        #[doc=$vardoc]
        pub struct $state {
            upstream_params: $upstream_params,
            upstream_state: $upstream_state,
            output_size: usize,
        }

        impl $state {
            /// Creates a new hashing context with a key.
            ///
            /// **WARNING!** If you plan to use it for variable output MAC, then
            /// make sure to compare codes in constant time! It can be done
            /// for example by using `subtle` crate.
            pub fn new_keyed(key: &[u8], output_size: usize) -> Self {
                let mut upstream_params = <$upstream_params>::new();
                upstream_params.key(key);
                upstream_params.hash_length(output_size);
                let upstream_state = upstream_params.to_state();
                Self { upstream_params, upstream_state, output_size }
            }

            /// Updates the hashing context with more data.
            fn update(&mut self, data: &[u8]) {
                self.upstream_state.update(data);
            }
        }

        impl Default for $state {
            fn default() -> Self { Self::new_keyed(&[], <$out_bytes_typenum>::to_usize()) }
        }

        impl BlockInput for $state {
            type BlockSize = $block_bytes_typenum;
        }

        impl Update for $state {
            fn update(&mut self, data: impl AsRef<[u8]>) {
                self.update(data.as_ref());
            }
        }

        impl VariableOutputDirty for $state {
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size == 0 || output_size > <$out_bytes_typenum>::to_usize() {
                    return Err(InvalidOutputSize);
                }
                Ok(Self::new_keyed(&[], output_size))
            }

            fn output_size(&self) -> usize {
                self.output_size
            }

            fn finalize_variable_dirty(&mut self, f: impl FnOnce(&[u8])) {
                f(self.upstream_state.finalize().as_bytes());
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.upstream_state = self.upstream_params.to_state();
            }
        }

        opaque_debug::implement!($state);
        digest::impl_write!($state);

        #[derive(Clone)]
        #[doc=$doc]
        pub struct $fix_state {
            upstream_params: $upstream_params,
            upstream_state: $upstream_state,
        }

        impl Default for $fix_state {
            fn default() -> Self {
                let upstream_params = <$upstream_params>::new();
                let upstream_state = upstream_params.to_state();
                Self { upstream_params, upstream_state }
            }
        }

        impl BlockInput for $fix_state {
            type BlockSize = $block_bytes_typenum;
        }

        impl Update for $fix_state {
            fn update(&mut self, data: impl AsRef<[u8]>) {
                self.upstream_state.update(data.as_ref());
            }
        }

        impl FixedOutputDirty for $fix_state {
            type OutputSize = $out_bytes_typenum;

            fn finalize_into_dirty(&mut self, out: &mut Output)  {
                out.copy_from_slice(self.upstream_state.finalize().as_bytes());
            }
        }

        impl Reset for $fix_state {
            fn reset(&mut self) {
                self.upstream_state = self.upstream_params.to_state();
            }
        }

        impl NewMac for $fix_state {
            type KeySize = $key_bytes_typenum;

            fn new(key: &GenericArray<u8, $key_bytes_typenum>) -> Self {
                let mut upstream_params = <$upstream_params>::new();
                upstream_params.key(&key[..]);
                let upstream_state = upstream_params.to_state();
                Self { upstream_params, upstream_state }
            }

            fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
                if key.len() > <$key_bytes_typenum>::to_usize() {
                    Err(InvalidKeyLength)
                } else {
                    let mut upstream_params = <$upstream_params>::new();
                    upstream_params.key(key);
                    let upstream_state = upstream_params.to_state();
                    Ok(Self { upstream_params, upstream_state })
                }
            }
        }

        impl Mac for $fix_state {
            type OutputSize = $out_bytes_typenum;

            fn update(&mut self, data: &[u8]) { self.upstream_state.update(data); }

            fn reset(&mut self) {
                <Self as Reset>::reset(self)
            }

            fn finalize(self) -> crypto_mac::Output<Self> {
                crypto_mac::Output::new(GenericArray::clone_from_slice(self.upstream_state.finalize().as_bytes()))
            }
        }

        opaque_debug::implement!($fix_state);
        digest::impl_write!($fix_state);
    }
}

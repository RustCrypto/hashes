macro_rules! gost94_impl {
    ($state:ident, $sbox:expr) => {
        use digest::generic_array::typenum::U32;
        use digest::generic_array::GenericArray;
        use digest::impl_write;
        use digest::{BlockInput, FixedOutput, Reset, Update};
        use $crate::gost94::{Block, Gost94, SBox};

        /// GOST94 state
        #[derive(Clone)]
        pub struct $state {
            sh: Gost94,
        }

        impl Default for $state {
            fn default() -> Self {
                $state {
                    sh: Gost94::new($sbox, Block::default()),
                }
            }
        }

        impl BlockInput for $state {
            type BlockSize = U32;
        }

        impl Update for $state {
            fn update(&mut self, input: impl AsRef<[u8]>) {
                let input = input.as_ref();
                self.sh.update(input);
            }
        }

        impl FixedOutput for $state {
            type OutputSize = U32;

            fn finalize_fixed(self) -> GenericArray<u8, Self::OutputSize> {
                self.sh.finalize_fixed()
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.sh.reset()
            }
        }

        impl_opaque_debug!($state);
        impl_write!($state);
    };
}

macro_rules! gost94_impl {
    ($state:ident, $sbox:expr) => {
        use digest::{consts::U32, BlockInput, FixedOutputDirty, Reset, Update};
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

        impl FixedOutputDirty for $state {
            type OutputSize = U32;

            fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
                self.sh.finalize_into_dirty(out)
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.sh.reset()
            }
        }

        opaque_debug::implement!($state);
        digest::impl_write!($state);
    };
}

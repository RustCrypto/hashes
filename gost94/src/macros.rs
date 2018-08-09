macro_rules! gost94_impl {
    ($state:ident, $sbox:expr) => {

    use $crate::gost94::{Gost94, SBox, Block};
    use digest::{Input, BlockInput, FixedOutput};
    use digest::generic_array::GenericArray;
    use digest::generic_array::typenum::U32;

    #[derive(Clone)]
    pub struct $state {
        sh: Gost94
    }

    impl $state {
        pub fn new() -> Self {
            $state{sh: Gost94::new($sbox, Block::default())}
        }
    }

    impl Default for $state {
        fn default() -> Self {
            Self::new()
        }
    }

    impl BlockInput for $state {
        type BlockSize = U32;
    }

    impl Input for $state {
        fn process(&mut self, input: &[u8]) {
            self.sh.process(input);
        }
    }

    impl FixedOutput for $state {
        type OutputSize = U32;

        fn fixed_result(&mut self) -> GenericArray<u8, Self::OutputSize> {
            self.sh.fixed_result()
        }
    }

    impl_opaque_debug!($state);
    impl_write!($state);
}}

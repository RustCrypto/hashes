macro_rules! gost94_impl {
    ($state:ident, $sbox:expr) => {

    use $crate::gost94::{Gost94, SBox, Block};
    use generic_array::typenum::U32;
    use digest;
    use generic_array::GenericArray;

    #[derive(Clone, Copy)]
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

    impl digest::BlockInput for $state {
        type BlockSize = U32;
    }

    impl digest::Input for $state {
        fn process(&mut self, input: &[u8]) {
            self.sh.process(input);
        }
    }

    impl digest::FixedOutput for $state {
        type OutputSize = U32;

        fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
            self.sh.fixed_result()
        }
    }
}}

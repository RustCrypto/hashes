macro_rules! impl_groestl {
    ($state:ident, $output:ident, $block:ident) => (
        #[derive(Clone)]
        pub struct $state {
            groestl: Groestl<$block>,
        }

        impl Default for $state {
            fn default() -> Self {
                $state { groestl: Groestl::new($output::to_usize()).unwrap() }
            }
        }

        impl BlockInput for $state {
            type BlockSize = $block;
        }

        impl Input for $state {
            fn input<B: AsRef<[u8]>>(&mut self, input: B) {
                let input = input.as_ref();
                self.groestl.process(input);
            }
        }

        impl FixedOutput for $state {
            type OutputSize = $output;

            fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
                let block = self.groestl.finalize();
                let n = block.len() - Self::OutputSize::to_usize();
                GenericArray::clone_from_slice( &block[n..])
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.groestl.reset()
            }
        }

        impl_opaque_debug!($state);
        impl_write!($state);
    )
}


macro_rules! impl_variable_groestl {
    ($state:ident, $block:ident, $min:expr, $max:expr) => (
        #[derive(Clone)]
        pub struct $state {
            groestl: Groestl<$block>,
        }

        impl BlockInput for $state {
            type BlockSize = $block;
        }

        impl Input for $state {
            fn input<B: AsRef<[u8]>>(&mut self, input: B) {
                self.groestl.process(input.as_ref());
            }
        }

        impl VariableOutput for $state {
            fn new(output_size: usize)
                -> Result<Self, InvalidOutputSize>
            {
                if output_size == $min || output_size > $max {
                    return Err(InvalidOutputSize);
                }
                Ok($state { groestl: Groestl::new(output_size).unwrap() })
            }

            fn output_size(&self) -> usize {
                self.groestl.output_size
            }

            fn variable_result<F: FnOnce(&[u8])>(mut self, f: F) {
                let block = self.groestl.finalize();
                let n = block.len() - self.groestl.output_size;
                f(&block[n..]);
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.groestl.reset()
            }
        }

        impl_opaque_debug!($state);
        impl_write!($state);
    )
}

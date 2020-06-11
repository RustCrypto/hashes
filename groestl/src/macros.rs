macro_rules! impl_groestl {
    ($state:ident, $output:ident, $block:ident) => {
        #[derive(Clone)]
        pub struct $state {
            groestl: Groestl<$block>,
        }

        impl Default for $state {
            fn default() -> Self {
                $state {
                    groestl: Groestl::new($output::to_usize()).unwrap(),
                }
            }
        }

        impl BlockInput for $state {
            type BlockSize = $block;
        }

        impl Update for $state {
            fn update(&mut self, input: impl AsRef<[u8]>) {
                let input = input.as_ref();
                self.groestl.process(input);
            }
        }

        impl FixedOutputDirty for $state {
            type OutputSize = $output;

            fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
                let block = self.groestl.finalize();
                let n = block.len() - Self::OutputSize::to_usize();
                out.copy_from_slice(&block[n..])
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.groestl.reset()
            }
        }

        opaque_debug::implement!($state);
        digest::impl_write!($state);
    };
}

macro_rules! impl_variable_groestl {
    ($state:ident, $block:ident, $min:expr, $max:expr) => {
        #[derive(Clone)]
        pub struct $state {
            groestl: Groestl<$block>,
        }

        impl BlockInput for $state {
            type BlockSize = $block;
        }

        impl Update for $state {
            fn update(&mut self, input: impl AsRef<[u8]>) {
                self.groestl.process(input.as_ref());
            }
        }

        impl VariableOutputDirty for $state {
            fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
                if output_size == $min || output_size > $max {
                    return Err(InvalidOutputSize);
                }
                Ok($state {
                    groestl: Groestl::new(output_size).unwrap(),
                })
            }

            fn output_size(&self) -> usize {
                self.groestl.output_size
            }

            fn finalize_variable_dirty(&mut self, f: impl FnOnce(&[u8])) {
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

        opaque_debug::implement!($state);
        digest::impl_write!($state);
    };
}

macro_rules! impl_groestl {
    ($state:ident, $output:ident, $block:ident) => (
        #[derive(Copy, Clone)]
        pub struct $state {
            groestl: Groestl<$block>,
        }

        impl Default for $state {
            fn default() -> Self {
                $state{groestl: Groestl::new($output::to_usize()).unwrap()}
            }
        }

        impl digest::BlockInput for $state {
            type BlockSize = $block;
        }

        impl digest::Input for $state {
            fn process(&mut self, input: &[u8]) {
                self.groestl.process(input);
            }
        }

        impl digest::FixedOutput for $state {
            type OutputSize = $output;

            fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
                let block = self.groestl.finalize();
                let n = block.len() - Self::OutputSize::to_usize();
                GenericArray::clone_from_slice( &block[n..])
            }
        }
    )
}


macro_rules! impl_variable_groestl {
    ($state:ident, $block:ident, $min:expr, $max:expr) => (

        #[derive(Copy, Clone)]
        pub struct $state {
            groestl: Groestl<$block>,
        }

        impl $state {
            pub fn new(output_size: usize) -> Result<Self, digest::InvalidLength> {
                if output_size == $min || output_size > $max {
                    return Err(digest::InvalidLength);
                }
                Ok($state {groestl: Groestl::new(output_size).unwrap()})
            }
        }

        impl digest::BlockInput for $state {
            type BlockSize = $block;
        }

        impl digest::Input for $state {
            fn process(&mut self, input: &[u8]) {
                self.groestl.process(input);
            }
        }

        impl digest::VariableOutput for $state {
            fn variable_result(self, buffer: &mut [u8])
                -> Result<&[u8], digest::InvalidLength>
            {
                if buffer.len() != self.groestl.output_size {
                    return Err(digest::InvalidLength);
                }
                let block = self.groestl.finalize();
                let n = block.len() - self.groestl.output_size;
                buffer.copy_from_slice(&block[n..]);
                Ok(buffer)
            }
        }

    )
}
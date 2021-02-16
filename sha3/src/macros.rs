macro_rules! sha3_impl {
    (
        $name:ident, $full_name:ident, $output_size:ident,
        $rate:ident, $padding:ty, $alg_name:expr,
    ) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name {
            state: Sha3State,
        }

        impl UpdateCore for $name {
            type BlockSize = $rate;
            type Buffer = BlockBuffer<$rate>;

            fn update_blocks(&mut self, blocks: &[GenericArray<u8, $rate>]) {
                for block in blocks {
                    self.state.absorb_block(block)
                }
            }
        }

        impl FixedOutputCore for $name {
            type OutputSize = $output_size;

            #[inline]
            fn finalize_fixed_core(
                &mut self,
                buffer: &mut BlockBuffer<Self::BlockSize>,
                out: &mut GenericArray<u8, Self::OutputSize>,
            ) {
                let block = buffer.pad_with::<$padding>();
                self.state.absorb_block(block);

                let n = out.len();
                self.state.as_bytes(|state| {
                    out.copy_from_slice(&state[..n]);
                });
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

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;
    };
}

macro_rules! shake_impl {
    (
        $name:ident, $full_name:ident, $reader:ident, $reader_full:ident,
        $rate:ident, $padding:ty, $alg_name:expr,
    ) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name {
            state: Sha3State,
        }

        impl UpdateCore for $name {
            type BlockSize = $rate;
            type Buffer = BlockBuffer<$rate>;

            #[inline]
            fn update_blocks(&mut self, blocks: &[GenericArray<u8, $rate>]) {
                for block in blocks {
                    self.state.absorb_block(block)
                }
            }
        }

        impl ExtendableOutputCore for $name {
            type ReaderCore = $reader;

            #[inline]
            fn finalize_xof_core(
                &mut self,
                buffer: &mut BlockBuffer<Self::BlockSize>,
            ) -> Self::ReaderCore {
                let block = buffer.pad_with::<$padding>();
                self.state.absorb_block(block);
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

        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " reader state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $reader {
            state: Sha3State,
        }

        impl XofReaderCore for $reader {
            type BlockSize = $rate;

            #[inline]
            fn read_block(&mut self) -> GenericArray<u8, Self::BlockSize> {
                let mut block = GenericArray::<u8, Self::BlockSize>::default();
                let n = block.len();
                self.state.as_bytes(|state| {
                    block.copy_from_slice(&state[..n]);
                });
                self.state.apply_f();
                block
            }
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;

        #[doc = $alg_name]
        #[doc = " reader state."]
        pub type $reader_full = XofReaderCoreWrapper<$name>;
    };
}

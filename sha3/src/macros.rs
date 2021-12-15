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
                let block = buffer.pad_with_zeros();
                block[pos] = $pad;
                let n = block.len();
                block[n - 1] |= 0x80;

                self.state.absorb_block(block);

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

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;
    };
}

macro_rules! impl_shake {
    (
        $name:ident, $full_name:ident, $reader:ident, $reader_full:ident,
        $rate:ident, $pad:expr, $alg_name:expr,
    ) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name {
            state: Sha3State,
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
                let block = buffer.pad_with_zeros();
                block[pos] = $pad;
                let n = block.len();
                block[n - 1] |= 0x80;

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

        impl BlockSizeUser for $reader {
            type BlockSize = $rate;
        }

        impl XofReaderCore for $reader {
            #[inline]
            fn read_block(&mut self) -> Block<Self> {
                let mut block = Block::<Self>::default();
                self.state.as_bytes(&mut block);
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

use crate::{
    CSHAKE_PAD, DEFAULT_ROUND_COUNT as ROUNDS, PLEN, SHAKE_PAD, Sha3XofReaderCore, xor_block,
};
use core::fmt;
use digest::{
    CustomizedInit, HashMarker, Reset,
    consts::{U136, U168},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, ExtendableOutputCore,
        UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::Unsigned,
};

macro_rules! impl_cshake {
    (
        $name:ident, $full_name:ident, $reader_name:ident, $rate:ident, $alg_name:expr
    ) => {
        #[doc = $alg_name]
        #[doc = " core hasher."]
        #[derive(Clone, Default)]
        pub struct $name {
            state: [u64; PLEN],
            initial_state: [u64; PLEN],
        }

        impl $name {
            /// Creates a new CSHAKE instance with the given function name and customization.
            ///
            /// Note that the function name is intended for use by NIST and should only be set to
            /// values defined by NIST. You probably don't need to use this function.
            pub fn new_with_function_name(function_name: &[u8], customization: &[u8]) -> Self {
                let mut state = Self::default();

                if function_name.is_empty() && customization.is_empty() {
                    return state;
                }

                #[inline(always)]
                pub(crate) fn left_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
                    b[1..].copy_from_slice(&val.to_be_bytes());
                    let i = b[1..8].iter().take_while(|&&a| a == 0).count();
                    b[i] = (8 - i) as u8;
                    &b[i..]
                }

                let mut buffer = Buffer::<Self>::default();
                let mut b = [0u8; 9];
                buffer.digest_blocks(left_encode($rate::to_u64(), &mut b), |blocks| {
                    state.update_blocks(blocks)
                });
                buffer.digest_blocks(
                    left_encode(8 * (function_name.len() as u64), &mut b),
                    |blocks| state.update_blocks(blocks),
                );
                buffer.digest_blocks(function_name, |blocks| state.update_blocks(blocks));
                buffer.digest_blocks(
                    left_encode(8 * (customization.len() as u64), &mut b),
                    |blocks| state.update_blocks(blocks),
                );
                buffer.digest_blocks(customization, |blocks| state.update_blocks(blocks));
                state.update_blocks(&[buffer.pad_with_zeros()]);
                state.initial_state = state.state;
                state
            }
        }

        impl CustomizedInit for $name {
            #[inline]
            fn new_customized(customization: &[u8]) -> Self {
                Self::new_with_function_name(&[], customization)
            }
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    xor_block(&mut self.state, block);
                    keccak::p1600(&mut self.state, ROUNDS);
                }
            }
        }

        impl ExtendableOutputCore for $name {
            type ReaderCore = Sha3XofReaderCore<$rate>;

            #[inline]
            fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
                let pos = buffer.get_pos();
                let mut block = buffer.pad_with_zeros();
                let pad = if self.initial_state == [0; PLEN] {
                    SHAKE_PAD
                } else {
                    CSHAKE_PAD
                };
                block[pos] = pad;
                let n = block.len();
                block[n - 1] |= 0x80;

                xor_block(&mut self.state, &block);
                keccak::p1600(&mut self.state, ROUNDS);

                Sha3XofReaderCore::new(&self.state)
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.state = self.initial_state;
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    use digest::zeroize::Zeroize;
                    self.state.zeroize();
                    self.initial_state.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $name {}

        impl SerializableState for $name {
            // TODO: implement properly with U400
            type SerializedStateSize = digest::consts::U0;

            fn serialize(&self) -> SerializedState<Self> {
                todo!()
            }

            fn deserialize(
                _serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                todo!()
            }
        }

        digest::newtype_xof_hash!(
            #[doc = $alg_name]
            #[doc = " hasher."]
            pub struct $full_name($name);
            #[doc = $alg_name]
            #[doc = " XOF reader."]
            pub struct $reader_name(Sha3XofReaderCore<$rate>);
        );

        impl CustomizedInit for $full_name {
            #[inline]
            fn new_customized(customization: &[u8]) -> Self {
                Self::new_with_function_name(&[], customization)
            }
        }

        impl $full_name {
            /// Creates a new cSHAKE instance with the given function name and customization.
            ///
            /// Note that the function name is intended for use by NIST and should only be set to
            /// values defined by NIST. You probably don't need to use this function.
            pub fn new_with_function_name(function_name: &[u8], customization: &[u8]) -> Self {
                Self {
                    core: $name::new_with_function_name(function_name, customization),
                    buffer: Default::default(),
                }
            }
        }
    };
}

impl_cshake!(CShake128Core, CShake128, CShake128Reader, U168, "cSHAKE128");
impl_cshake!(CShake256Core, CShake256, CShake256Reader, U136, "cSHAKE256");

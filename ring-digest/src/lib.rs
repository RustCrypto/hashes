#[macro_use] pub extern crate digest;
#[macro_use] extern crate opaque_debug;
extern crate ring;

use std::mem;

pub use digest::Digest;
use digest::{
    generic_array::{typenum::*, GenericArray},
    FixedOutput, Input, Reset,
};
use ring::digest::Context;

macro_rules! impl_digest {
    (
        $(#[doc = $doc:tt])*
        $name:ident, $hasher:ident, $hash_size:ident
    ) => {
        $(#[doc = $doc])*
        #[derive(Clone)]
        pub struct $name(Context);

        impl Default for $name {
            fn default() -> Self {
                $name(Context::new(&ring::digest::$hasher))
            }
        }

        impl Input for $name {
            fn input<B: AsRef<[u8]>>(&mut self, input: B) {
                self.0.update(input.as_ref())
            }
        }

        impl FixedOutput for $name {
            type OutputSize = $hash_size;

            #[allow(unused_mut)]
            fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
                GenericArray::clone_from_slice(self.0.finish().as_ref())
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                mem::replace(&mut self.0, Context::new(&ring::digest::$hasher));
            }
        }

        impl_opaque_debug!($name);
        impl_write!($name);
    };
}

impl_digest!(
    /// Structure representing the state of a SHA-1 computation
    Sha1, SHA1, U20
);
impl_digest!(
    /// Structure representing the state of a SHA-256 computation
    Sha256, SHA256, U32
);
impl_digest!(
    /// Structure representing the state of a SHA-384 computation
    Sha384, SHA384, U48
);
impl_digest!(
    /// Structure representing the state of a SHA-512 computation
    Sha512, SHA512, U64
);
impl_digest!(
    /// Structure representing the state of a SHA-512/256 computation
    Sha512_256, SHA512_256, U32
);

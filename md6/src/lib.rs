#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

mod compress;
pub(crate) mod consts;
mod md6;

use digest::{
    consts::{U28, U32, U48, U64},
    core_api::{CoreWrapper, CtVariableCoreWrapper, RtVariableCoreWrapper},
};

pub use digest::{Digest, Update, VariableOutput};

use crate::md6::Md6VarCore;

/// Md6 which allows variable output size at runtime
pub type Md6Var = RtVariableCoreWrapper<Md6VarCore>;
/// Core hash function for Md6 generic over output size
pub type Md6Core<OutSize> = CtVariableCoreWrapper<Md6VarCore, OutSize>;
/// Md6 generic over output size.
pub type Md6<OutSize> = CoreWrapper<Md6Core<OutSize>>;
/// Md6 with 224-bit output
pub type Md6_224 = CoreWrapper<Md6Core<U28>>;
/// Md6 with 256-bit output
pub type Md6_256 = CoreWrapper<Md6Core<U32>>;
/// Md6 with 384-bit output
pub type Md6_384 = CoreWrapper<Md6Core<U48>>;
/// Md6 with 512-bit output
pub type Md6_512 = CoreWrapper<Md6Core<U64>>;

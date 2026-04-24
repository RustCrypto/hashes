#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]
#![forbid(unsafe_code)]

pub use digest::{self, CustomizedInit, ExtendableOutput, Update, XofReader};

mod consts;
mod cxof;
mod reader;
mod xof;

pub use cxof::AsconCxof128;
pub use reader::AsconXof128Reader;
pub use xof::AsconXof128;

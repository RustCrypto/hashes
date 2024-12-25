// Adapted from the original C code: https://github.com/brbsh/samp-plugin-md6


#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

mod md6;
mod md6_compress;
mod md6_consts;

pub use md6::*;
pub use md6_compress::*;

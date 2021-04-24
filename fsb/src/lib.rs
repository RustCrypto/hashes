#![allow(non_snake_case)]
#[allow(dead_code)]
#[macro_use]
mod macros;
mod pi;

use crate::pi::PI;

use whirlpool::Whirlpool;

use std::convert::TryInto;

use block_buffer::BlockBuffer;
use digest::{generic_array::GenericArray, Digest};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

fsb_impl!(Fsb160, 160, U60, U20, 5 << 18, 80, 640, 653, 1120);
fsb_impl!(Fsb224, 224, U84, U28, 7 << 18, 112, 896, 907, 1568);
fsb_impl!(Fsb256, 256, U96, U32, 1 << 21, 128, 1024, 1061, 1792);
fsb_impl!(Fsb384, 384, U115, U48, 23 << 16, 184, 1472, 1483, 2392);
fsb_impl!(Fsb512, 512, U155, U64, 31 << 16, 248, 1984, 1987, 3224);

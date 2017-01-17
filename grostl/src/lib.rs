extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;
extern crate generic_array;

use generic_array::ArrayLength;
use generic_array::typenum::{
    Cmp, Compare, Greater, Less, Same,
    U32, U33, U64, U65, U128,
};

mod grostl;
mod matrix;

pub type GrostlSmall<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U64>,
          Compare<OutputSize, U33>: Same<Less>
    = grostl::Grostl<OutputSize, U64>;

pub type GrostlBig<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U64>,
          Compare<OutputSize, U32>: Same<Greater>,
          Compare<OutputSize, U65>: Same<Less>
    = grostl::Grostl<OutputSize, U128>;

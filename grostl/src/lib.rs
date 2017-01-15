extern crate byte_tools;
extern crate digest;
extern crate generic_array;

use generic_array::ArrayLength;
use generic_array::typenum::{
    Cmp, Compare, Greater, Less, Same,
    U256, U257, U512, U513, U1024,
};

mod grostl;
mod matrix;

pub type GrostlSmall<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U512>,
          Compare<OutputSize, U257>: Same<Less>
    = grostl::Grostl<OutputSize, U512>;

pub type GrostlBig<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U512>,
          Compare<OutputSize, U256>: Same<Greater>,
          Compare<OutputSize, U513>: Same<Less>
    = grostl::Grostl<OutputSize, U1024>;

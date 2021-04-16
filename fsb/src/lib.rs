#![allow(non_snake_case)]
#[allow(dead_code)]

#[macro_use]
mod macros;
mod pi;

// mod fsb160;
// mod fsb224;

// U60 is because (S - R) / 8
// fsb_impl!(Fsb160, 160, U60, U20, 5 << 18, 80, 640, 653, 1120);
fsb_impl!(Fsb224, 224, U84, U28, 7 << 18, 112, 896, 907, 1568);


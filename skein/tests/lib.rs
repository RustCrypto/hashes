#![no_std]
use digest::{
    dev::fixed_test,
    generic_array::typenum::{U128, U32, U64},
    new_test,
};

new_test!(skein256_32, "skein256_32", skein::Skein256<U32>, fixed_test);
new_test!(skein512_32, "skein512_32", skein::Skein512<U32>, fixed_test);
new_test!(
    skein1024_32,
    "skein1024_32",
    skein::Skein1024<U32>,
    fixed_test
);
new_test!(skein256_64, "skein256_64", skein::Skein256<U64>, fixed_test);
new_test!(skein512_64, "skein512_64", skein::Skein512<U64>, fixed_test);
new_test!(
    skein1024_64,
    "skein1024_64",
    skein::Skein1024<U64>,
    fixed_test
);
new_test!(
    skein1024_128,
    "skein1024_128",
    skein::Skein1024<U128>,
    fixed_test
);

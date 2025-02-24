use skein::{
    Skein256, Skein512, Skein1024,
    consts::{U32, U64, U128},
    digest::{dev::fixed_test, new_test},
};

new_test!(skein256_32, "skein256_32", Skein256<U32>, fixed_test);
new_test!(skein256_64, "skein256_64", Skein256<U64>, fixed_test);
new_test!(skein512_32, "skein512_32", Skein512<U32>, fixed_test);
new_test!(skein512_64, "skein512_64", Skein512<U64>, fixed_test);
new_test!(skein1024_32, "skein1024_32", Skein1024<U32>, fixed_test);
new_test!(skein1024_64, "skein1024_64", Skein1024<U64>, fixed_test);
new_test!(skein1024_128, "skein1024_128", Skein1024<U128>, fixed_test);

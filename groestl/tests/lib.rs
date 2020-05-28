#![no_std]

use digest::{dev::digest_test, new_test};

new_test!(
    groestl_224_main,
    "groestl224",
    groestl::Groestl224,
    digest_test
);
new_test!(
    groestl_256_main,
    "groestl256",
    groestl::Groestl256,
    digest_test
);
new_test!(
    groestl_384_main,
    "groestl384",
    groestl::Groestl384,
    digest_test
);
new_test!(
    groestl_512_main,
    "groestl512",
    groestl::Groestl512,
    digest_test
);

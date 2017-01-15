#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate generic_array;
extern crate grostl;

use crypto_tests::hash::{Test, main_test};
use generic_array::typenum::{U28, U32, U48, U64};

#[test]
fn grostl_224_main() {
    let tests = new_tests!("grostl224/test1");
    main_test::<grostl::GrostlSmall<U28>>(&tests);
}

#[test]
fn grostl_256_main() {
    let tests = new_tests!(
        "grostl256/test1",
        "grostl256/test2",
        "grostl256/test3"
    );
    main_test::<grostl::GrostlSmall<U32>>(&tests);
}

#[test]
fn grostl_384_main() {
    let tests = new_tests!("grostl384/test1");
    main_test::<grostl::GrostlBig<U48>>(&tests);
}

#[test]
fn grostl_512_main() {
    let tests = new_tests!("grostl512/test1");
    main_test::<grostl::GrostlBig<U64>>(&tests);
}

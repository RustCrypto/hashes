#![no_std]

use digest::dev::{digest_test, variable_test};
use digest::new_test;

new_test!(
    blake2b_fixed,
    "blake2b/fixed",
    blake2::Blake2b512,
    digest_test
);
new_test!(
    blake2b_variable,
    "blake2b/variable",
    blake2::Blake2bVar,
    variable_test
);
new_test!(
    blake2s_variable,
    "blake2s/variable",
    blake2::Blake2sVar,
    variable_test
);

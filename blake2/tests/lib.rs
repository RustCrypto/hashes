#![no_std]
#[macro_use]
extern crate digest;
extern crate blake2;
extern crate hex_literal;

use digest::dev::{digest_test, variable_test};

new_test!(blake2b_fixed, "blake2b/fixed", blake2::Blake2b, digest_test);
new_test!(blake2b_variable, "blake2b/variable", blake2::VarBlake2b, variable_test);
new_test!(blake2s_variable, "blake2s/variable", blake2::VarBlake2s, variable_test);
new_test!(blake2bp, "blake2bp", blake2::Blake2bp, digest_test);
new_test!(blake2sp, "blake2sp", blake2::Blake2sp, digest_test);

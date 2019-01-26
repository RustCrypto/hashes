extern crate blake;
#[macro_use]
extern crate digest;

use digest::dev::digest_test;

new_test!(blake224, "blake224", blake::Blake224, digest_test);
new_test!(blake256, "blake256", blake::Blake256, digest_test);
new_test!(blake384, "blake384", blake::Blake384, digest_test);
new_test!(blake512, "blake512", blake::Blake512, digest_test);

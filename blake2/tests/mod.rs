#[cfg(feature = "reset")]
use digest::dev::fixed_reset_test as fixed_test;
#[cfg(not(feature = "reset"))]
use digest::dev::fixed_test;
use digest::new_test;

new_test!(blake2b_kat, blake2::Blake2b512, fixed_test);

// TODO(tarcieri): port tests over from the `digest` crate
// new_test!(blake2b_variable_kat, blake2::Blake2bVar, variable_test);
// new_test!(blake2s_variable_kat, blake2::Blake2sVar, variable_test);

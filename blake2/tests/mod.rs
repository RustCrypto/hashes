#[cfg(feature = "reset")]
use digest::dev::fixed_reset_test as fixed_test;
#[cfg(not(feature = "reset"))]
use digest::dev::fixed_test;
use digest::new_test;

new_test!(blake2b_kat, blake2::Blake2b512, fixed_test);

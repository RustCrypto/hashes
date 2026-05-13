use digest::dev::xof_reset_test;
use digest::new_test;

new_test!(shake128_kat, shake::Shake128, xof_reset_test);
new_test!(shake256_kat, shake::Shake256, xof_reset_test);

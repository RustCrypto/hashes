#[cfg(feature = "reset")]
use digest::dev::{fixed_reset_test as fixed_fn, variable_reset_test as variable_fn};
#[cfg(not(feature = "reset"))]
use digest::dev::{fixed_test as fixed_fn, variable_test as variable_fn};
use digest::new_test;

new_test!(blake2b_fixed, "blake2b/fixed", blake2::Blake2b512, fixed_fn,);
new_test!(
    blake2b_variable,
    "blake2b/variable",
    blake2::Blake2bVar,
    variable_fn,
);
new_test!(
    blake2s_variable,
    "blake2s/variable",
    blake2::Blake2sVar,
    variable_fn,
);

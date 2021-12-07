#[cfg(not(feature = "reset"))]
use digest::new_mac_test as new_test;
#[cfg(feature = "reset")]
use digest::new_resettable_mac_test as new_test;

new_test!(blake2b_mac, "blake2b/mac", blake2::Blake2bMac512);
new_test!(blake2s_mac, "blake2s/mac", blake2::Blake2sMac256);

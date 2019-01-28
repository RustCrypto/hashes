#![no_std]
#[macro_use]
extern crate digest;
extern crate jh_x86_64;

use digest::dev::digest_test;

new_test!(long_224, "LongMsgKAT_224", jh_x86_64::Jh224, digest_test);
new_test!(long_256, "LongMsgKAT_256", jh_x86_64::Jh256, digest_test);
new_test!(long_384, "LongMsgKAT_384", jh_x86_64::Jh384, digest_test);
new_test!(long_512, "LongMsgKAT_512", jh_x86_64::Jh512, digest_test);

new_test!(short_224, "ShortMsgKAT_224", jh_x86_64::Jh224, digest_test);
new_test!(short_256, "ShortMsgKAT_256", jh_x86_64::Jh256, digest_test);
new_test!(short_384, "ShortMsgKAT_384", jh_x86_64::Jh384, digest_test);
new_test!(short_512, "ShortMsgKAT_512", jh_x86_64::Jh512, digest_test);

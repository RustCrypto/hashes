use digest::dev::digest_test;
use digest::new_test;

new_test!(fsb160_main, "fsb160", fsb::Fsb160, digest_test);
new_test!(fsb224_main, "fsb224", fsb::Fsb224, digest_test);
new_test!(fsb256_main, "fsb256", fsb::Fsb256, digest_test);
new_test!(fsb384_main, "fsb384", fsb::Fsb384, digest_test);
new_test!(fsb512_main, "fsb512", fsb::Fsb512, digest_test);

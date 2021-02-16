use digest::{dev::digest_test, new_test};

new_test!(tiger, "tiger", tiger::Tiger, digest_test);
new_test!(tiger2, "tiger2", tiger::Tiger2, digest_test);

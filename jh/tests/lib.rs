use digest::{dev::fixed_test, new_test};

new_test!(long_224, "LongMsgKAT_224", jh::Jh224, fixed_test);
new_test!(long_256, "LongMsgKAT_256", jh::Jh256, fixed_test);
new_test!(long_384, "LongMsgKAT_384", jh::Jh384, fixed_test);
new_test!(long_512, "LongMsgKAT_512", jh::Jh512, fixed_test);

new_test!(short_224, "ShortMsgKAT_224", jh::Jh224, fixed_test);
new_test!(short_256, "ShortMsgKAT_256", jh::Jh256, fixed_test);
new_test!(short_384, "ShortMsgKAT_384", jh::Jh384, fixed_test);
new_test!(short_512, "ShortMsgKAT_512", jh::Jh512, fixed_test);

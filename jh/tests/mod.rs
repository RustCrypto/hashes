use digest::{dev::fixed_test, new_test};

new_test!(jh224_long_kat, jh::Jh224, fixed_test);
new_test!(jh256_long_kat, jh::Jh256, fixed_test);
new_test!(jh384_long_kat, jh::Jh384, fixed_test);
new_test!(jh512_long_kat, jh::Jh512, fixed_test);

new_test!(jh224_short_kat, jh::Jh224, fixed_test);
new_test!(jh256_short_kat, jh::Jh256, fixed_test);
new_test!(jh384_short_kat, jh::Jh384, fixed_test);
new_test!(jh512_short_kat, jh::Jh512, fixed_test);

use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::{hash_rt_outsize_serialization_test, hash_serialization_test, new_test};
use groestl::{
    Digest, Groestl224, Groestl256, Groestl384, Groestl512, GroestlLongVar, GroestlShortVar,
};
use hex_literal::hex;

new_test!(groestl_224_main, "groestl224", Groestl224, fixed_reset_test);
new_test!(groestl_256_main, "groestl256", Groestl256, fixed_reset_test);
new_test!(groestl_384_main, "groestl384", Groestl384, fixed_reset_test);
new_test!(groestl_512_main, "groestl512", Groestl512, fixed_reset_test);

#[rustfmt::skip]
hash_serialization_test!(
    groestl_224_serialization,
    Groestl224,
    hex!("
        22b4f94ab7689d6434484d06ae89401b
        722a240fb27e61ec2b16bcd4a7356a5b
        cbd38299d0bf12e0aed4e157e66f3936
        2470e38d59247c03b911539fdf1c590f
        01000000000000001c01130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);
#[rustfmt::skip]
hash_serialization_test!(
    groestl_256_serialization,
    Groestl256,
    hex!("
        d52426ab8dbd5022f8c30afca94d27d8
        37e2407b311f65ee2926b33d0ea59209
        0db3463c0f6e272d40ad97ad88a5ffe6
        444e3bbf31165508937a71b9b5e4c690
        01000000000000002001130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);
#[rustfmt::skip]
hash_serialization_test!(
    groestl_384_serialization,
    Groestl384,
    hex!("
        7b6e411adea4d26a564b6c1717001184
        cb8ca1d57c461635e98ef0d4acc02e00
        cab78a23a12ae339f70e612a4aad386a
        5f8fe9024262e3ef35fda0e0aecf819c
        d274889e334b330ce0f116e0c74c5df1
        1085f942d65089d7e0d6494a83e6bdea
        fa03861e95cc5c13e1afb8312332f79d
        70ee8dc1e6bbdb5644bfaa0bfc7e3674
        01000000000000003001130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);
#[rustfmt::skip]
hash_serialization_test!(
    groestl_512_serialization,
    Groestl512,
    hex!("
        503f2a766eed3a15b43ecbf90f840447
        588fe26f14cc63fd7d79a375c920b776
        e3a443149c735f4161ef31ff8ccb0afb
        dba6ce50239411294623568f43e8d337
        5f236f50e6aad6409661bb5348ef0451
        b6f470a42a63fa3613e7091ab0044014
        e3535f6ece66f3a19ac53d98f60bd896
        2c879ab89e4990e1a39418d8a94bde45
        01000000000000004001130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);
#[rustfmt::skip]
hash_rt_outsize_serialization_test!(
    groestl_short_var_serialization,
    GroestlShortVar,
    hex!("
        d549d951b61b5caa7ad964c6595b4473
        0161feb244d70c75c562b63374224a2f
        228bffde579c78368b8b507021cdacb9
        a17412ae9027f8f4cb061c9c9d94a77e
        01000000000000000113000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        0000000000000000001f
    ")
);
#[rustfmt::skip]
hash_rt_outsize_serialization_test!(
    groestl_long_var_serialization,
    GroestlLongVar,
    hex!("
        d2038487f42a7bc6ac0c172db0aa20a4
        f878e618ffefd63b11517a039b374088
        2ce6345f0eb746fa8abd6446f4d52d13
        3395872ae812d0c10a7569c03872eb59
        22a38a10f240cc6c2b62c60b95461bc6
        80e0a2e2452561a28edcd59a1ca4bf7f
        7237d1395d84e76a2061218d084d9112
        9e4ae07a2dc86b2c67e1acc188eceba4
        01000000000000000113000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        0000000000000000003f
    ")
);

#[test]
fn groestl224_rand() {
    let mut h = Groestl224::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("2000744c2f85a7fb4733e97da8db00069dd6defa9186dac3461dfeb8"),
    );
}

#[test]
fn groestl256_rand() {
    let mut h = Groestl256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("aac71c789678f627a6474605322ae98d1647e47f405d00b1461b90ee5f0cfbc4"),
    );
}

#[test]
fn groestl384_rand() {
    let mut h = Groestl384::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "dab78eea895a6dde0c53dc02fc79c7986f5d6811618ca6e5922f01e8aca9bfeb"
            "20ed5eda4130bf0ab474ac0b6f0290f8"
        ),
    );
}

#[test]
fn groestl512_rand() {
    let mut h = Groestl512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "7e4d8257c217c7ae59331126e0f984f145e9789862de7c099675ac29e46424ef"
            "e93543974fa7113190d492f607f629a03db35ec5551abcb2785ae145fd3c543f"
        ),
    );
}

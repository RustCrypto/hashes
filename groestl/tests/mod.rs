use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::{hash_serialization_test, new_test};
use groestl::{Digest, Groestl224, Groestl256, Groestl384, Groestl512};
use hex_literal::hex;

new_test!(groestl224_kat, Groestl224, fixed_reset_test);
new_test!(groestl256_kat, Groestl256, fixed_reset_test);
new_test!(groestl384_kat, Groestl384, fixed_reset_test);
new_test!(groestl512_kat, Groestl512, fixed_reset_test);

hash_serialization_test!(groestl224_serialization, Groestl224);
hash_serialization_test!(groestl256_serialization, Groestl256);
hash_serialization_test!(groestl384_serialization, Groestl384);
hash_serialization_test!(groestl512_serialization, Groestl512);

// TODO: re-enable after fixing impl in the macro
/*
hash_rt_outsize_serialization_test!(
    groestl_short_var_serialization,
    GroestlShortVar,
    hex!(
        "d549d951b61b5caa7ad964c6595b4473"
        "0161feb244d70c75c562b63374224a2f"
        "228bffde579c78368b8b507021cdacb9"
        "a17412ae9027f8f4cb061c9c9d94a77e"
        "01000000000000000113000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "0000000000000000001f"
    )
);
hash_rt_outsize_serialization_test!(
    groestl_long_var_serialization,
    GroestlLongVar,
    hex!(
        "d2038487f42a7bc6ac0c172db0aa20a4"
        "f878e618ffefd63b11517a039b374088"
        "2ce6345f0eb746fa8abd6446f4d52d13"
        "3395872ae812d0c10a7569c03872eb59"
        "22a38a10f240cc6c2b62c60b95461bc6"
        "80e0a2e2452561a28edcd59a1ca4bf7f"
        "7237d1395d84e76a2061218d084d9112"
        "9e4ae07a2dc86b2c67e1acc188eceba4"
        "01000000000000000113000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "0000000000000000003f"
    )
);
*/

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

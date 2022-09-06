#![no_std]

use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::{hash_serialization_test, new_test};
use hex_literal::hex;
use shabal::{Digest, Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};

new_test!(shabal192_main, "shabal192", Shabal192, fixed_reset_test);
new_test!(shabal224_main, "shabal224", Shabal224, fixed_reset_test);
new_test!(shabal256_main, "shabal256", Shabal256, fixed_reset_test);
new_test!(shabal384_main, "shabal384", Shabal384, fixed_reset_test);
new_test!(shabal512_main, "shabal512", Shabal512, fixed_reset_test);

#[rustfmt::skip]
hash_serialization_test!(
    shabal192_serialization,
    Shabal192,
    hex!("
        5039204617bc74833d85392827f8a4dc
        9ac8eda6c9de1b56f61879157d15deac
        9b8c2170e578116fa9464c2269a06be6
        65f5414e6218dc7633f9528e4872e06b
        79a2845f8064b30810b49e6c2db35ca3
        09a43507045a84ddf7d479f5e0da4191
        e158f608380f63990965023f56134aba
        f3cf6558c25b0a72e9c247dd2eb57f91
        6fb115aac5d870af0bf646f4e663cd11
        7fb0af3bbce91a4a40876cdabe7b95c9
        bfe92dd7ae31110726fb1b33d2183477
        02000000000000001801130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);

#[rustfmt::skip]
hash_serialization_test!(
    shabal224_serialization,
    Shabal224,
    hex!("
        9d466b087ab69391e8e9c3d92409d6d9
        5b49b1a1124a021722c149eeff1507ae
        598db0e5fcf9def16798a1841b286ba8
        8e60a2d16df506393e697d0bea6b6df1
        d2bac527efff9e0340193eef05b8f10e
        1a4c2d868e35a3d2300a985daf12f98d
        f298de0343d8a8254dc9ee87705af69d
        e57d96abc34fc92e5d8194f3b4438399
        3bc21d38311f40fb6717051629a8f2b8
        61d3f46aa9cdb7cf37981781f31aee26
        f3e2686c3a18a94ced2612722e6c03b5
        02000000000000001c01130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);

#[rustfmt::skip]
hash_serialization_test!(
    shabal256_serialization,
    Shabal256,
    hex!("
        b3d27330c9676be3d9b6200924583db5
        bee08342ab935cc068781eac890bd7cc
        cf71dfaf4158eb717291c661377f4841
        1eddf2a0a72b10b1662660a0428acaad
        9b1509b2cea51490544eb24320314eda
        4d8aa275a7bbcf4d783878626c17d570
        157583a9e4f8ccd3428b70a74d093688
        121b31571bb00244209b8157f6b10b59
        fa1c06007633ca58d530851c06fe878e
        a7c3f69e3d9dc271dc0bb5f2e0d14182
        ea242c80ee16e72c6ca9d3ac0fd76356
        02000000000000002001130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);

#[rustfmt::skip]
hash_serialization_test!(
    shabal384_serialization,
    Shabal384,
    hex!("
        355cab8881202f5f3a6cdebbf4fa985c
        bfa232bb4567c140cc4ede6f47eb9e96
        3b21275bf636a63cbdbb0b71ad10098a
        079e51e4330e04633a80e3bb8670bfb3
        4e4cf6eaa1054d4be2d9353d4e1f223e
        c9235b5b9afaff4fc388b396f9d67d0b
        28f421695a4bc615fafa20975ddb2ab8
        4d9f20d8d28824c1bf1551a48aac281a
        f10046f41d03f02d5eb1406272a1443b
        2f1b1986f2d98581bb590d3e310bd0bc
        9e43aa352f9129bea46e1c77e3039eda
        02000000000000003001130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);

#[rustfmt::skip]
hash_serialization_test!(
    shabal512_serialization,
    Shabal512,
    hex!("
        e569f34e6d01c4b1a10d664ad63b9a4c
        651175399c30ea4cd7a115c6911035cb
        c56fdb4940d150277318888b7ca64bde
        be55acc63dc4a7459f79ef4246e0216e
        c556c1a2af7907815b17782e6d14f2f0
        74c4f46b7c22813e52c34d2987c484ab
        2121f9815a8dc69b7ac924125646c869
        9b4141fbad6679751f8c1624a15aebc4
        27de6fa08d6fdee2c94ae0567c0e5f46
        578da939e824cf529f094aa979e92354
        992b0863d7dcc6e911766049be4af617
        02000000000000004001130000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000
    ")
);

#[test]
fn shabal192_rand() {
    let mut h = Shabal192::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("a3e480026be158db97976a895b7a015e9e5205986ebc8a89"),
    );
}

#[test]
fn shabal224_rand() {
    let mut h = Shabal224::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("a09bedfed92fdffc896e6043ec175aa1f07383c65bde990a3661e3d0"),
    );
}

#[test]
fn shabal256_rand() {
    let mut h = Shabal256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("53252a6467450aa1afc1ac25efb493aa65b70e5b2280a4bed7f672c0cfe6f40e"),
    );
}

#[test]
fn shabal384_rand() {
    let mut h = Shabal384::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "15b8ece81e490848c997dba603523be8842c654262e5adc29138d22a01ff0c9f"
            "2b0a0dc9f3e7702ac3598fb1b9ff2db2"
        ),
    );
}

#[test]
fn shabal512_rand() {
    let mut h = Shabal512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "66f091bc2ba6c571a776441c08ee0711752344ba8b4c88ea17a078baa70d8c0a"
            "717b7da24e765867cfcf273a43a58f90e07c0130d1e97adc49f66a0502536e82"
        ),
    );
}

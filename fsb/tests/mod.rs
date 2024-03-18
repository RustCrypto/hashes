use digest::{
    dev::{feed_rand_16mib, fixed_reset_test},
    hash_serialization_test, new_test,
};
use fsb::{Digest, Fsb160, Fsb224, Fsb256, Fsb384, Fsb512};
use hex_literal::hex;

new_test!(fsb160_main, "fsb160", Fsb160, fixed_reset_test);
new_test!(fsb224_main, "fsb224", Fsb224, fixed_reset_test);
new_test!(fsb256_main, "fsb256", Fsb256, fixed_reset_test);
new_test!(fsb384_main, "fsb384", Fsb384, fixed_reset_test);
new_test!(fsb512_main, "fsb512", Fsb512, fixed_reset_test);

#[rustfmt::skip]
hash_serialization_test!(
    fsb160_serialization,
    Fsb160,
    hex!("
        e269a086505e9493fa92ed509f6cdce8
        51dd58654160a8c8a499a953a479c169
        d46c0576d8e7b262341087f58eb3dc9d
        3002451f8f0d484cbdc8b342afef13e5
        4f2fce12e400eca0a6bc0b8837f999c3
        01000000000000000113000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        0000000000
    ")
);
#[rustfmt::skip]
hash_serialization_test!(
    fsb224_serialization,
    Fsb224,
    hex!("
        bfba3bbd79050b4428d239ec4eb25277
        b228898bd26c04ccf11e052944e72b61
        aae3f1a0a6cdb862d87fac21fefb1dc1
        4074cfc45d8994087dc70d1d5308b6b1
        f68f6eea5d886904dfcab198e62f6c97
        67ae365fc648b1bb7d00f65ff276373a
        7a1b4d80efdd7af5fce3b0e93371172a
        01000000000000000113000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000
    ")
);

#[rustfmt::skip]
hash_serialization_test!(
    fsb256_serialization,
    Fsb256,
    hex!("
        6c4fef5401baa1825e74fe2a150dd746
        55ba10d8fa2db4ee3e6925de2cf4a83a
        5121e2ded528f92613ec858045c1bdd1
        5a11ce8bd4df1a3f409dfc9d1025d333
        360f30a342f417018fcf0ff1c5dddb04
        2a18453d707d27721e57fd182d932945
        89a1c3ef007e6bb3b59f2a361094e21d
        6c72d213545a6612a2adc547968a03e9
        01000000000000000113000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        000000000000000000
    ")
);

#[rustfmt::skip]
hash_serialization_test!(
    fsb384_serialization,
    Fsb384,
    hex!("
        41825b73ae6b5cdc91b8b70723dc1f92
        97fec62f09c17c75a2326e3d7664efb5
        df1104db5c711016d161187f3174ef77
        f5e0545c917d01375537d15cf90c838d
        2f5fd5a294c7012d80a0f6a6240f90f9
        a6976812ec60fdd35bbc1a064287308e
        1d916cb4d59c02b19ab2d20e1b9b2acb
        e826c4d0022db322e3314fe0cf232cdd
        75b61c653bf30569ca76dd11bd032d03
        bc83a0e59964eb5dd77a22d0a459de63
        ab5ff6ce1207a9daed690c36399f7306
        43a1628e0f33650a0100000000000000
        01130000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000
    ")
);

#[rustfmt::skip]
hash_serialization_test!(
    fsb512_serialization,
    Fsb512,
    hex!("
        4feff733b532b0767d0bbe8804f60ebc
        bbf33aa6796e608d37e6e24dcf216636
        31312286c6efa794b237f05df2838526
        cb5120291a53566bb784ff32d2ea5464
        693cd68fc52a37375160c0a4f4b8dae8
        06703a98720180c4abaa2c195a6ede59
        ed68fc5caae6172003ad9195d7ae7747
        10d7a0c46772a7216e553a39dbeac282
        fa2848e7038eec7c78f7da35db4cf8ea
        d35f2f140ec49203f1d3afe24fe4100a
        9d0cc5fdb1e964ed48fe786e2bfdabe4
        70c148f65c67c21cc6794b8e1eb90e6a
        39800334a2016e2081f5a458fcd348d8
        778dc4090066f3906b835a1283c97569
        4e1dc38fef18dd35d2d4f283d0bc1502
        db72a91871a23bc40100000000000000
        01130000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        000000000000000000000000
    ")
);

#[test]
fn fsb160_rand() {
    let mut h = Fsb160::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("40b7538be5e51978690d1a92fe12a7f25f0a7f08")
    );
}

#[test]
fn fsb224_rand() {
    let mut h = Fsb224::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("0ec203ccec7cbf0cadd32e5dc069d0b4215a104c4dad5444944a0d09")
    );
}

#[test]
fn fsb256_rand() {
    let mut h = Fsb256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("eecb42832a2b03bc91beb1a56ddf2973c962b1aeb22f278e9d78a7a8879ebba7")
    );
}

#[test]
fn fsb384_rand() {
    let mut h = Fsb384::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "f17533ed4d4484434715e63bc8e801c9cfe988c38d47d3b4be0409571360aa2f"
            "b360b2804c14f606906b323e7901c09e"
        )
    );
}

#[test]
fn fsb512_rand() {
    let mut h = Fsb512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "957a7733643e075ab7a3b04607800a6208a26b008bdaee759a3a635bb9b5b708"
            "3531725783505468bf438f2a0a96163bbe0775468a11c93db9994c466b2e7d8c"
        )
    );
}

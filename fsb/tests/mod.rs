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
        0100000000000000e269a086505e9493
        fa92ed509f6cdce851dd58654160a8c8
        a499a953a479c169d46c0576d8e7b262
        341087f58eb3dc9d3002451f8f0d484c
        bdc8b342afef13e54f2fce12e400eca0
        a6bc0b8837f999c30113000000000000
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
        0100000000000000bfba3bbd79050b44
        28d239ec4eb25277b228898bd26c04cc
        f11e052944e72b61aae3f1a0a6cdb862
        d87fac21fefb1dc14074cfc45d899408
        7dc70d1d5308b6b1f68f6eea5d886904
        dfcab198e62f6c9767ae365fc648b1bb
        7d00f65ff276373a7a1b4d80efdd7af5
        fce3b0e93371172a0113000000000000
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
        01000000000000006c4fef5401baa182
        5e74fe2a150dd74655ba10d8fa2db4ee
        3e6925de2cf4a83a5121e2ded528f926
        13ec858045c1bdd15a11ce8bd4df1a3f
        409dfc9d1025d333360f30a342f41701
        8fcf0ff1c5dddb042a18453d707d2772
        1e57fd182d93294589a1c3ef007e6bb3
        b59f2a361094e21d6c72d213545a6612
        a2adc547968a03e90113000000000000
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
        010000000000000041825b73ae6b5cdc
        91b8b70723dc1f9297fec62f09c17c75
        a2326e3d7664efb5df1104db5c711016
        d161187f3174ef77f5e0545c917d0137
        5537d15cf90c838d2f5fd5a294c7012d
        80a0f6a6240f90f9a6976812ec60fdd3
        5bbc1a064287308e1d916cb4d59c02b1
        9ab2d20e1b9b2acbe826c4d0022db322
        e3314fe0cf232cdd75b61c653bf30569
        ca76dd11bd032d03bc83a0e59964eb5d
        d77a22d0a459de63ab5ff6ce1207a9da
        ed690c36399f730643a1628e0f33650a
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
        01000000000000004feff733b532b076
        7d0bbe8804f60ebcbbf33aa6796e608d
        37e6e24dcf21663631312286c6efa794
        b237f05df2838526cb5120291a53566b
        b784ff32d2ea5464693cd68fc52a3737
        5160c0a4f4b8dae806703a98720180c4
        abaa2c195a6ede59ed68fc5caae61720
        03ad9195d7ae774710d7a0c46772a721
        6e553a39dbeac282fa2848e7038eec7c
        78f7da35db4cf8ead35f2f140ec49203
        f1d3afe24fe4100a9d0cc5fdb1e964ed
        48fe786e2bfdabe470c148f65c67c21c
        c6794b8e1eb90e6a39800334a2016e20
        81f5a458fcd348d8778dc4090066f390
        6b835a1283c975694e1dc38fef18dd35
        d2d4f283d0bc1502db72a91871a23bc4
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
        h.finalize()[..],
        hex!("40b7538be5e51978690d1a92fe12a7f25f0a7f08")[..]
    );
}

#[test]
fn fsb224_rand() {
    let mut h = Fsb224::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("0ec203ccec7cbf0cadd32e5dc069d0b4215a104c4dad5444944a0d09")[..]
    );
}

#[test]
fn fsb256_rand() {
    let mut h = Fsb256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("eecb42832a2b03bc91beb1a56ddf2973c962b1aeb22f278e9d78a7a8879ebba7")[..]
    );
}

#[test]
#[rustfmt::skip]
fn fsb384_rand() {
    let mut h = Fsb384::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            f17533ed4d4484434715e63bc8e801c9cfe988c38d47d3b4be0409571360aa2f
            b360b2804c14f606906b323e7901c09e
        ")[..]
    );
}

#[test]
#[rustfmt::skip]
fn fsb512_rand() {
    let mut h = Fsb512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            957a7733643e075ab7a3b04607800a6208a26b008bdaee759a3a635bb9b5b708
            3531725783505468bf438f2a0a96163bbe0775468a11c93db9994c466b2e7d8c
        ")[..]
    );
}

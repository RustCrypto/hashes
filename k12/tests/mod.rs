use core::iter;
use hex_literal::hex;
use k12::{
    digest::{ExtendableOutput, Update},
    KangarooTwelve, KangarooTwelveCore,
};

fn digest_and_box(data: &[u8], n: usize) -> Box<[u8]> {
    let mut h = KangarooTwelve::default();
    h.update(data);
    h.finalize_boxed(n)
}

#[test]
#[rustfmt::skip]
fn empty() {
    // Source: reference paper
    assert_eq!(
        digest_and_box(b"", 32)[..],
        hex!("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")[..]
    );

    assert_eq!(
        digest_and_box(b"", 64)[..],
        hex!("
            1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5
            4269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71
        ")[..]
    );

    assert_eq!(
        digest_and_box(b"", 10032)[10000..],
        hex!("e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d")[..]
    );
}

#[test]
fn pat_m() {
    let expected = [
        hex!("2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f"),
        hex!("6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888"),
        hex!("0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c"),
        hex!("cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0"),
        hex!("8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe"),
        hex!("844d610933b1b9963cbdeb5ae3b6b05cc7cbd67ceedf883eb678a0a8e0371682"),
        hex!("3c390782a8a4e89fa6367f72feaaf13255c8d95878481d3cd8ce85f58e880af8"),
    ];
    for i in 0..5
    /*NOTE: can be up to 7 but is slow*/
    {
        let len = 17usize.pow(i);
        let m: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let result = digest_and_box(&m, 32);
        assert_eq!(result[..], expected[i as usize][..]);
    }
}

#[test]
fn pat_c() {
    let expected = [
        hex!("fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583"),
        hex!("d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4"),
        hex!("c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74"),
        hex!("75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf"),
    ];
    for i in 0..4 {
        let m: Vec<u8> = iter::repeat(0xFF).take(2usize.pow(i) - 1).collect();
        let len = 41usize.pow(i);
        let c: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let mut h = KangarooTwelve::from_core(KangarooTwelveCore::new(&c));
        h.update(&m);
        let result = h.finalize_boxed(32);
        assert_eq!(result[..], expected[i as usize][..]);
    }
}

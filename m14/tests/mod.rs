use core::iter;
use hex_literal::hex;
use m14::{
    digest::{ExtendableOutput, Update},
    MarsupilamiFourteen, MarsupilamiFourteenCore,
};

fn digest_and_box(data: &[u8], n: usize) -> Box<[u8]> {
    let mut h = MarsupilamiFourteen::default();
    h.update(data);
    h.finalize_boxed(n)
}

#[test]
#[rustfmt::skip]
fn empty() {
    // Source: reference paper
    assert_eq!(
        digest_and_box(b"", 32)[..],
        hex!("6f66ef1474eb53807aa329257c768bb88893d9f086e51da2f5c80d17ca0fc57d")[..]
    );

    assert_eq!(
        digest_and_box(b"", 64)[..],
        hex!("
            6f66ef1474eb53807aa329257c768bb88893d9f086e51da2f5c80d17ca0fc57d
            5a24fac879014f8b30a3fdf5ac56ebafa219eb891d4bbbab7e1df3b27205b459
        ")[..]
    );

    assert_eq!(
        digest_and_box(b"", 10032)[10000..],
        hex!("c09322de1513d0cd604728f36d11adff58b93f776381095a071921eafb30e1e3")[..]
    );
}

#[test]
fn pat_m() {
    let expected = [
        hex!("cc05ebc928156c7a03540085355c47c6aea1d07dc811cdded0e4c367f8d99368"),
        hex!("aa764fd8b38f19976a305cb007f19384b210a5c7b0fc4499d6f83c6227bff850"),
        hex!("f18a6e250b1cc83dea89ffbb4de56a8e70041c71fc5b17a2aaab05c606aa6bf2"),
        hex!("0ac89b11a06f46b2f6feeff046c97e90dc02910ae509b8739cfea5df1df90b82"),
        hex!("35af0a5fc6c4d111fbc68f879d05506aafd300b5ab136986d7aed8a9f1be331e"),
        hex!("0c982c5d5334e27cc6591cda308dfa6b4fdd736aadbe64536bdef83c1d496ba0"),
    ];
    for i in 0..5
    /*NOTE: can be up to 6 but is slow*/
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
        hex!("e6c23ceeab2089d14dc3b088fdfe6d4418bf8a6f330fb3edcc300cd81e1bef2f"),
        hex!("2bab75b31b8c3049abeb7674774771b64f59225be20e930ebdbf8e37c24fad69"),
        hex!("732a60c308bebf5f7b3d3e8f0d26e324c04bab4197ca0a608b0befaa25ea5976"),
        hex!("61583cdfaa64ab60e77b8c8bdd0ad088f9d760b2944f7d64c5dd81ce7e92d96b"),
    ];
    for i in 0..4 {
        let m: Vec<u8> = iter::repeat(0xFF).take(2usize.pow(i) - 1).collect();
        let len = 41usize.pow(i);
        let c: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let mut h = MarsupilamiFourteen::from_core(MarsupilamiFourteenCore::new(&c));
        h.update(&m);
        let result = h.finalize_boxed(32);
        assert_eq!(result[..], expected[i as usize][..]);
    }
}

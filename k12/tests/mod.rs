use core::iter;
use hex_literal::hex;
use k12::{
    Kt128, Kt256,
    digest::{ExtendableOutput, Update},
};

macro_rules! digest_and_box {
    ($name:ident, $hasher:ty) => {
        fn $name(data: &[u8], n: usize) -> Box<[u8]> {
            let mut h = <$hasher>::default();
            h.update(data);
            h.finalize_boxed(n)
        }
    };
}

digest_and_box!(kt128_digest_and_box, Kt128);
digest_and_box!(kt256_digest_and_box, Kt256);

// Source: <https://www.rfc-editor.org/rfc/rfc9861.html#section-5>

#[test]
fn kt128_empty() {
    assert_eq!(
        kt128_digest_and_box(b"", 32)[..],
        hex!("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")[..]
    );

    assert_eq!(
        kt128_digest_and_box(b"", 64)[..],
        hex!(
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"
            "4269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71"
        )[..],
    );

    assert_eq!(
        kt128_digest_and_box(b"", 10032)[10000..],
        hex!("e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d")[..]
    );
}

#[test]
fn kt256_empty() {
    assert_eq!(
        kt256_digest_and_box(b"", 64)[..],
        hex!(
            "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404"
            "e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9"
        )[..],
    );

    assert_eq!(
        kt256_digest_and_box(b"", 128)[..],
        hex!(
            "b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404"
            "e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9"
            "b0925319d8ea1e121a609821ec19efea89e6d08daee1662b69c840289f188ba8"
            "60f55760b61f82114c030c97e5178449608ccd2cd2d919fc7829ff69931ac4d0"
        )[..],
    );

    assert_eq!(
        kt256_digest_and_box(b"", 10064)[10000..],
        hex!(
            "ad4a1d718cf950506709a4c33396139b4449041fc79a05d68da35f1e453522e0"
            "56c64fe94958e7085f2964888259b9932752f3ccd855288efee5fcbb8b563069"
        )[..],
    );
}

#[test]
fn kt128_pat_m() {
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
        let result = kt128_digest_and_box(&m, 32);
        assert_eq!(result[..], expected[i as usize][..]);
    }
}

#[test]
fn kt256_pat_m() {
    let expected = [
        hex!(
            "0d005a194085360217128cf17f91e1f71314efa5564539d444912e3437efa17f"
            "82db6f6ffe76e781eaa068bce01f2bbf81eacb983d7230f2fb02834a21b1ddd0"
        ),
        hex!(
            "1ba3c02b1fc514474f06c8979978a9056c8483f4a1b63d0dccefe3a28a2f323e"
            "1cdcca40ebf006ac76ef0397152346837b1277d3e7faa9c9653b19075098527b"
        ),
        hex!(
            "de8ccbc63e0f133ebb4416814d4c66f691bbf8b6a61ec0a7700f836b086cb029"
            "d54f12ac7159472c72db118c35b4e6aa213c6562caaa9dcc518959e69b10f3ba"
        ),
        hex!(
            "647efb49fe9d717500171b41e7f11bd491544443209997ce1c2530d15eb1ffbb"
            "598935ef954528ffc152b1e4d731ee2683680674365cd191d562bae753b84aa5"
        ),
        hex!(
            "b06275d284cd1cf205bcbe57dccd3ec1ff6686e3ed15776383e1f2fa3c6ac8f0"
            "8bf8a162829db1a44b2a43ff83dd89c3cf1ceb61ede659766d5ccf817a62ba8d"
        ),
        hex!(
            "9473831d76a4c7bf77ace45b59f1458b1673d64bcd877a7c66b2664aa6dd149e"
            "60eab71b5c2bab858c074ded81ddce2b4022b5215935c0d4d19bf511aeeb0772"
        ),
        hex!(
            "0652b740d78c5e1f7c8dcc1777097382768b7ff38f9a7a20f29f413bb1b3045b"
            "31a5578f568f911e09cf44746da84224a5266e96a4a535e871324e4f9c7004da"
        ),
    ];
    for i in 0..5
    /*NOTE: can be up to 7 but is slow*/
    {
        let len = 17usize.pow(i);
        let m: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let result = kt256_digest_and_box(&m, 64);
        assert_eq!(result[..], expected[i as usize][..]);
    }
}

#[test]
fn kt128_pat_c() {
    let expected = [
        hex!("fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583"),
        hex!("d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4"),
        hex!("c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74"),
        hex!("75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf"),
    ];
    for i in 0..4 {
        let m: Vec<u8> = iter::repeat_n(0xFF, 2usize.pow(i) - 1).collect();
        let len = 41usize.pow(i);
        let c: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let mut h = Kt128::new(&c);
        h.update(&m);
        let result = h.finalize_boxed(32);
        assert_eq!(result[..], expected[i as usize][..]);
    }
}

#[test]
fn kt256_pat_c() {
    let expected = [
        hex!(
            "9280f5cc39b54a5a594ec63de0bb99371e4609d44bf845c2f5b8c316d72b1598"
            "11f748f23e3fabbe5c3226ec96c62186df2d33e9df74c5069ceecbb4dd10eff6"
        ),
        hex!(
            "47ef96dd616f200937aa7847e34ec2feae8087e3761dc0f8c1a154f51dc9ccf8"
            "45d7adbce57ff64b639722c6a1672e3bf5372d87e00aff89be97240756998853"
        ),
        hex!(
            "3b48667a5051c5966c53c5d42b95de451e05584e7806e2fb765eda959074172c"
            "b438a9e91dde337c98e9c41bed94c4e0aef431d0b64ef2324f7932caa6f54969"
        ),
        hex!(
            "e0911cc00025e1540831e266d94add9b98712142b80d2629e643aac4efaf5a3a"
            "30a88cbf4ac2a91a2432743054fbcc9897670e86ba8cec2fc2ace9c966369724"
        ),
    ];
    for i in 0..4 {
        let m: Vec<u8> = iter::repeat_n(0xFF, 2usize.pow(i) - 1).collect();
        let len = 41usize.pow(i);
        let c: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let mut h = Kt256::new(&c);
        h.update(&m);
        let result = h.finalize_boxed(64);
        assert_eq!(result[..], expected[i as usize][..]);
    }
}

#[test]
fn kt128_input_multiple_of_chunk_size_minus_one() {
    // generated with reference python implementation
    let expected = [
        hex!("1b577636f723643e990cc7d6a659837436fd6a103626600eb8301cd1dbe553d6"),
        hex!("e3ded52118ea64eaf04c7531c6ccb95e32924b7c2b87b2ce68ff2f2ee46e84ef"),
        hex!("daacf62e434bdd126fbe9e61fae38d1429e9dddfaf8f999095585c3cbf366a4a"),
        hex!("eac3722b4b7db10af973ed7ca60e113a19fab895b46476a9aac51ead099e6ba4"),
    ];
    for (i, exp_res) in expected.iter().enumerate() {
        let len = 8192 * (i + 1) - 1;
        let m: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let result = kt128_digest_and_box(&m, 32);
        assert_eq!(result[..], exp_res[..]);
    }
}

#[test]
fn kt128_input_multiple_of_chunk_size() {
    // generated with reference python implementation
    let expected = [
        hex!("48f256f6772f9edfb6a8b661ec92dc93b95ebd05a08a17b39ae3490870c926c3"),
        hex!("82778f7f7234c83352e76837b721fbdbb5270b88010d84fa5ab0b61ec8ce0956"),
        hex!("f4082a8fe7d1635aa042cd1da63bf235f91c231886c29896f9fe3818c60cd360"),
        hex!("d14f8dc243c206004ca8a996997e5ae16a8bdda288f6c90d20d7c43c1a408618"),
    ];
    for (i, exp_res) in expected.iter().enumerate() {
        let len = 8192 * (i + 1);
        let m: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
        let result = kt128_digest_and_box(&m, 32);
        assert_eq!(result[..], exp_res[..]);
    }
}

use bash_prg_hash::{
    BashPrgHash1281, BashPrgHash1282, BashPrgHash1921, BashPrgHash1922, BashPrgHash2561,
    BashPrgHash2562,
};
use digest::{ExtendableOutput, TryCustomizedInit};
use hex_literal::hex;
use std::fmt::Debug;

#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    pub customization: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

pub(crate) fn bash_prg_hash_test<D>(
    &TestVector {
        customization,
        input,
        output,
    }: &TestVector,
) -> Result<(), &'static str>
where
    D: TryCustomizedInit + ExtendableOutput + Clone,
    <D as TryCustomizedInit>::Error: Debug,
{
    let mut hasher = D::try_new_customized(customization).unwrap();
    let mut buf = [0u8; 1024];
    let buf = &mut buf[..output.len()];
    // Test that it works when accepting the message all at once
    hasher.update(input);
    hasher.finalize_xof_into(buf);
    if buf != output {
        return Err("whole message");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    // Test that it works when accepting the message in chunks
    for n in 1..core::cmp::min(17, input.len()) {
        let mut hasher = D::try_new_customized(customization).unwrap();
        for chunk in input.chunks(n) {
            hasher.update(chunk);
        }
        hasher.finalize_xof_into(buf);
        if buf != output {
            return Err("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }

    Ok(())
}

macro_rules! new_bash_prg_hash_test {
    ($name:ident, $hasher:ty $(,)?) => {
        #[test]
        fn $name() {
            digest::dev::blobby::parse_into_structs!(
                include_bytes!(concat!("data/", stringify!($name), ".blb"));
                static TEST_VECTORS: &[TestVector { customization, input, output }];
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                if let Err(reason) = bash_prg_hash_test::<$hasher>(tv) {
                    panic!(
                        "\n\
                         Failed test #{i}\n\
                         reason:\t{reason}
                         test vector:\t{tv:?}\n"
                    );
                }
            }
        }
    };
}

// Test vectors generated with bee2 library: https://github.com/agievich/bee2
// Messages is the first N bytes of `beltH()` (belt S-box constant) for N = 0, 127, 128, 143, 144, 150
// Plus 3 tests with customization:
//   - 06075316 (4 bytes) + "Fifty four byte..." message
//   - 0102030405060708 (8 bytes) + "Fifty four byte..." message
//   - FFEEDDCC (4 bytes) + beltH()[0..100]
new_bash_prg_hash_test!(bashprg_l128_d1, BashPrgHash1281);
new_bash_prg_hash_test!(bashprg_l128_d2, BashPrgHash1282);
new_bash_prg_hash_test!(bashprg_l192_d1, BashPrgHash1921);
new_bash_prg_hash_test!(bashprg_l192_d2, BashPrgHash1922);
new_bash_prg_hash_test!(bashprg_l256_d1, BashPrgHash2561);
new_bash_prg_hash_test!(bashprg_l256_d2, BashPrgHash2562);

macro_rules! test_bash_prg_rand {
    ($name:ident, $hasher:ty, $expected:expr) => {
        #[test]
        fn $name() {
            let mut h = <$hasher>::default();
            digest::dev::feed_rand_16mib(&mut h);
            let mut output = [0u8; 64];
            h.finalize_xof_into(&mut output);
            assert_eq!(&output[..], $expected);
        }
    };
}

test_bash_prg_rand!(
    bashprg1282_rand,
    BashPrgHash1282,
    hex!(
        "BF15805CDEAE220A9DD50C325A4A0BDF326C6ED853CFA89592A9E2BEB4D0585C"
        "891AF66C1CA514390311FDFB51D467FC11439AE4907863A5C3861CDCF7F360EC"
    )
);

test_bash_prg_rand!(
    bashprg1921_rand,
    BashPrgHash1921,
    hex!(
        "82176D6DAF4F631E251CA41A7688FEB643B954383186C7902AB09D80EB5AB17C"
        "BA286D16912EBBACEC3D8143966107F6DFB5F4AC4F88B64F20AB49CEAD817E45"
    )
);

test_bash_prg_rand!(
    bashprg2562_rand,
    BashPrgHash2562,
    hex!(
        "AD07A8D61928296F4115F9E51AAA5FA986899BFDA8443F139D969600064EBCE2"
        "D591F583FA27F6B0F7E73DA2B29AF382AC2374C04463B91A27F1C48FEE8AAB2C"
    )
);

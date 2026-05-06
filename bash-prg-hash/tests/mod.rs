use bash_prg_hash::{BashPrgHash1282, BashPrgHash1921, BashPrgHash2562};
use digest::ExtendableOutput;
use digest::dev::TestVector;
use hex_literal::hex;

fn xof_test<D>(&TestVector { input, output }: &TestVector) -> Result<(), &'static str>
where
    D: Default + ExtendableOutput + Clone,
{
    let mut hasher = D::default();
    let mut buf = [0u8; 1024];
    let buf = &mut buf[..output.len()];
    // Test that it works when accepting the message all at once
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    hasher.finalize_xof_into(buf);
    if buf != output {
        return Err("whole message");
    }
    buf.iter_mut().for_each(|b| *b = 0);

    // Test that it works when accepting the message in chunks
    for n in 1..core::cmp::min(17, input.len()) {
        let mut hasher = D::default();
        for chunk in input.chunks(n) {
            hasher.update(chunk);
            hasher2.update(chunk);
        }
        hasher.finalize_xof_into(buf);
        if buf != output {
            return Err("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }

    Ok(())
}

// Test vectors from STB 34.101.77-2020 (Appendix A, Table A.5)
digest::new_test!(bashprg1282, BashPrgHash1282, xof_test);
digest::new_test!(bashprg1921, BashPrgHash1921, xof_test);
// Not in STB 34.101.77-2020, but included for completeness
digest::new_test!(bashprg2562, BashPrgHash2562, xof_test);

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

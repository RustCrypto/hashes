use bash_prg_hash::{BashPrgHash1282, BashPrgHash1921, BashPrgHash2562};
use digest::ExtendableOutput;
use digest::dev::xof_reset_test;
use hex_literal::hex;

// Test vectors from STB 34.101.77-2020 (Appendix A, Table A.5)
digest::new_test!(bashprg1282, BashPrgHash1282, xof_reset_test);
digest::new_test!(bashprg1921, BashPrgHash1921, xof_reset_test);
// Not in STB 34.101.77-2020, but included for completeness
digest::new_test!(bashprg2562, BashPrgHash2562, xof_reset_test);

macro_rules! test_bash_prg_rand {
    ($name:ident, $hasher:ty, $expected:expr) => {
        #[test]
        fn $name() {
            use bash_prg_hash::{HashLevel, SecurityLevel};
            let mut h = <$hasher>::default();
            digest::dev::feed_rand_16mib(&mut h);
            let mut output = vec![0u8; <<$hasher as HashLevel>::Level as SecurityLevel>::LEVEL / 4];
            h.finalize_xof_into(&mut output);
            assert_eq!(&output[..], $expected);
        }
    };
}

test_bash_prg_rand!(
    bashprg1282_rand,
    BashPrgHash1282,
    hex!("BF15805CDEAE220A9DD50C325A4A0BDF326C6ED853CFA89592A9E2BEB4D0585C")
);

test_bash_prg_rand!(
    bashprg1921_rand,
    BashPrgHash1921,
    hex!(
        "82176D6DAF4F631E251CA41A7688FEB643B954383186C7902AB09D80EB5AB17C
        BA286D16912EBBACEC3D8143966107F6"
    )
);

test_bash_prg_rand!(
    bashprg2562_rand,
    BashPrgHash2562,
    hex!(
        "AD07A8D61928296F4115F9E51AAA5FA986899BFDA8443F139D969600064EBCE2
        D591F583FA27F6B0F7E73DA2B29AF382AC2374C04463B91A27F1C48FEE8AAB2C"
    )
);

use ascon_xof128::{AsconCxof128, AsconXof128};
use core::fmt::Debug;
use digest::{
    CustomizedInit, ExtendableOutput,
    common::hazmat::SerializableState,
    dev::{feed_rand_16mib, xof_reset_test},
};
use hex_literal::hex;

// Test vectors from:
// https://github.com/ascon/ascon-c/blob/main/crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt
digest::new_test!(ascon_xof128_kat, AsconXof128, xof_reset_test);

/// Test vectors from:
/// https://github.com/ascon/ascon-c/blob/main/crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt
#[test]
fn ascon_cxof128_kat() {
    digest::dev::blobby::parse_into_structs!(
        include_bytes!("data/ascon_cxof128_kat.blb");
        static TEST_VECTORS: &[CxofTestVector { input, customization, output }];
    );

    for (i, tv) in TEST_VECTORS.iter().enumerate() {
        if let Err(reason) = cxof_reset_test::<AsconCxof128>(tv) {
            panic!(
                "\n\
                    Failed test #{i}:\n\
                    reason:\t{reason}\n\
                    test vector:\t{tv:?}\n"
            );
        }
    }
}

#[test]
fn ascon_xof128_rand() {
    let mut h = AsconXof128::default();
    feed_rand_16mib(&mut h);

    let ser_state = h.serialize();
    let ser_expected = include_bytes!("data/ascon_xof128_serialization.bin");
    assert_eq!(ser_state[..], ser_expected[..]);

    let expected_hash = hex!(
        "E06CA16A362949DE5D05743B663445BE6AD39CD22C2CED839FD937E31E58B1CC"
        "85E67F131C61AB55EEE4B8B90C060E078B9CAE1299394498C799C310C66286C8"
    );

    let mut buf = [0u8; 64];
    h.finalize_xof_into(&mut buf);
    assert_eq!(buf, expected_hash);

    h = AsconXof128::deserialize(&ser_state).unwrap();
    buf = [0u8; 64];
    h.finalize_xof_into(&mut buf);
    assert_eq!(buf, expected_hash);
}

#[test]
fn ascon_cxof128_rand() {
    let mut h = AsconCxof128::new_customized(b"randomized cxof test");
    feed_rand_16mib(&mut h);

    let ser_state = h.serialize();
    let ser_expected = include_bytes!("data/ascon_cxof128_serialization.bin");
    assert_eq!(ser_state[..], ser_expected[..]);

    let expected_hash = hex!(
        "3E797ECD4EB7373C7283078BFCC53E5B0645B083AF703146A527FEC3AE209E85"
        "DAA663270B7687540A221F87C44433906931BFE43BE3BA0333ADFAC62BC8EC1F"
    );

    let mut buf = [0u8; 64];
    h.finalize_xof_into(&mut buf);
    assert_eq!(buf, expected_hash);

    h = AsconCxof128::deserialize(&ser_state).unwrap();
    buf = [0u8; 64];
    h.finalize_xof_into(&mut buf);
    assert_eq!(buf, expected_hash);
}

#[derive(Debug, Clone, Copy)]
struct CxofTestVector {
    input: &'static [u8],
    customization: &'static [u8],
    output: &'static [u8],
}

/// Customized XOF test.
fn cxof_reset_test<D: ExtendableOutput + CustomizedInit + Debug + Clone>(
    &CxofTestVector {
        customization,
        input,
        output,
    }: &CxofTestVector,
) -> Result<(), &'static str> {
    let mut hasher = D::new_customized(customization);
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
        let mut hasher = D::new_customized(customization);
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

use digest::{CustomizedInit, ExtendableOutput};

#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    pub customization: &'static [u8],
    pub input: &'static [u8],
    pub output: &'static [u8],
}

pub(crate) fn cshake_test<D>(
    &TestVector {
        customization,
        input,
        output,
    }: &TestVector,
) -> Result<(), &'static str>
where
    D: CustomizedInit + ExtendableOutput + Clone,
{
    let mut hasher = D::new_customized(customization);
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
        let mut hasher = D::new_customized(customization);
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

macro_rules! new_cshake_test {
    ($name:ident, $hasher:ty $(,)?) => {
        #[test]
        fn $name() {
            digest::dev::blobby::parse_into_structs!(
                include_bytes!(concat!("data/", stringify!($name), ".blb"));
                static TEST_VECTORS: &[TestVector { customization, input, output }];
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                if let Err(reason) = cshake_test::<$hasher>(tv) {
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

new_cshake_test!(cshake128, cshake::CShake128);
new_cshake_test!(cshake256, cshake::CShake256);

// When bytepad output aligns exactly to the block boundary,
// no extra zero block should be appended (SP 800-185 2.3.3).
new_cshake_test!(cshake128_bytepad_block_aligned, cshake::CShake128);
new_cshake_test!(cshake256_bytepad_block_aligned, cshake::CShake256);

use core::fmt::Debug;
use digest::ExtendableOutput;

pub(crate) fn turbo_shake_test<D>(
    input: &[u8],
    output: &[u8],
    truncate_output: usize,
) -> Option<&'static str>
where
    D: ExtendableOutput + Default + Debug + Clone,
{
    let mut hasher = D::default();
    let mut buf = [0u8; 16 * 1024];
    let buf = &mut buf[..truncate_output + output.len()];
    // Test that it works when accepting the message all at once
    hasher.update(input);
    let mut hasher2 = hasher.clone();
    hasher.finalize_xof_into(buf);
    if &buf[truncate_output..] != output {
        return Some("whole message");
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
        if &buf[truncate_output..] != output {
            return Some("message in chunks");
        }
        buf.iter_mut().for_each(|b| *b = 0);
    }

    None
}

macro_rules! new_turbo_shake_test {
    ($name:ident, $test_name:expr, $hasher:ty, $test_func:ident $(,)?) => {
        #[test]
        fn $name() {
            use digest::dev::blobby::Blob4Iterator;
            let data = include_bytes!(concat!("data/", $test_name, ".blb"));

            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let [input, input_pattern_length, output, truncate_output] = row.unwrap();

                let input = if (input_pattern_length.len() == 0) {
                    input.to_vec()
                } else if (input.len() == 0) {
                    let pattern_length =
                        u64::from_be_bytes(input_pattern_length.try_into().unwrap());
                    let mut input = Vec::<u8>::new();
                    for value in 0..pattern_length {
                        input.push((value % 0xFB).try_into().unwrap());
                    }
                    input
                } else {
                    panic!(
                        "\
                        failed to read tests data\n\
                         input:\t{:02X?}\n\
                         input_pattern_length:\t{:02X?}\n",
                        input, input_pattern_length,
                    );
                };

                println!("before func: {:?}", truncate_output.len());

                if let Some(desc) = $test_func::<$hasher>(
                    &input,
                    output,
                    u64::from_be_bytes(truncate_output.try_into().unwrap())
                        .try_into()
                        .unwrap(),
                ) {
                    panic!(
                        "\n\
                         Failed test №{}: {}\n\
                         input:\t{:02X?}\n\
                         output:\t{:02X?}\n",
                        i, desc, &input, output,
                    );
                }
            }
        }
    };
}

new_turbo_shake_test!(
    turboshake128_6,
    "turboshake128_6",
    sha3::TurboShake128<6>,
    turbo_shake_test,
);
new_turbo_shake_test!(
    turboshake128_7,
    "turboshake128_7",
    sha3::TurboShake128<7>,
    turbo_shake_test,
);
new_turbo_shake_test!(
    turboshake256_6,
    "turboshake256_6",
    sha3::TurboShake256<6>,
    turbo_shake_test,
);

new_turbo_shake_test!(
    turboshake256_7,
    "turboshake256_7",
    sha3::TurboShake256<7>,
    turbo_shake_test,
);

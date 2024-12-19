use digest::crypto_common::KeyInit;
use digest::FixedOutput;
use digest::Update;
use hex_literal::hex;

use multimixer_128::Multimixer;

#[test]
fn multimixer_10_test() {
    let key = &hex!("4420823cfde6f1c26b30f90ec7dd01e4887534a20f0b0d04c36ed80e71e0fd77");
    let mut h = Multimixer::new(key.into());
    let data = [0; 100];
    digest::Update::update(&mut h, &data[..]);
}

#[test]
fn multimixer_simple_test() {
    let key = &hex!("4420823cfde6f1c26b30f90ec7dd01e4887534a20f0b0d04c36ed80e71e0fd77");
    let message = &hex!("b07670eb940bd5335f973daad8619b91ffc911f57cced458bbbf2ce03753c9bd");
    let mut h = Multimixer::new_from_slice(key).unwrap();
    h.update(message);
    assert_eq!(
        h.finalize_fixed().as_slice(),
        &hex!("aca6cbf6480d9b17bb9d13efbb3589596ca1ce7d3ae4edac586d77e22313b5189f6c97c2a910636df227850c398ca01b92ab25c1ccec360e4020eec91331a383")[..]
    );
}

#[test]
fn multimixer_simple_160_test() {
    let key = &hex!("0702f5a3c49364cc514d0f07c64a1dc2824228ec9b07121f42158c3cdd2e610eff428e62e5c7a889857c7d1e59b3db1fb4d366d9238825805a314d1e68db161b2ef0bd32a0144010e241cae40c8a2e80a62b9a11c41d85a04285c23b9b30d97d69a9adc8f63542e50f955066bdc7a631d1b040211699a0d598a3b48ba6043e4ca2a6a723e78ff5e8bac2281c4418fb807dadb9bdce9dedae550e4b807144395e");
    let message = &hex!("d21932883668852228256f58dd0bbcf9917066fc78d9e7bb60f62583d06704c2f927ced914b4ea036199023d9aa190d2d19de79a43e347538104d912bcd7cd90092e2e02c489ed8bbef6acc6e93bf7b54ad44b095885bc4193d38493d78cddabf86efbcdd92e2042694c750d34814ff532cc5f012dda1a6fd8b11834d63c878e5bf5186d2cc73fe596fec93bf5364cc5675583d593fc6dacf83404b1881ce199");
    let mut h = Multimixer::new_from_slice(key).unwrap();
    h.update(message);
    assert_eq!(
        h.finalize_fixed().as_slice(),
        &hex!("fa80bf97fff5b9b014b0691c27907b1f04ac2debd24f964b9ae546d269d6eca934762c68a377114213591c04a762bb331eafe51633c06ee7304fc8dca2c88604")[..]
    );
}

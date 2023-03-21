// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::HashMap;
use std::include_str;

use spectral::prelude::{asserting, OrderedAssertions};

use ascon_hash::{
    AsconAHash, AsconAXof, AsconHash, AsconXof, Digest, ExtendableOutput, Reset, XofReader,
};

#[derive(Debug)]
struct TestVector {
    count: u32,
    message: Vec<u8>,
    digest: Vec<u8>,
}

impl TestVector {
    fn new(count: &str, message: &str, digest: &str) -> Self {
        Self {
            count: count.parse().unwrap(),
            message: hex::decode(message).unwrap(),
            digest: hex::decode(digest).unwrap(),
        }
    }
}

fn run_tv<H: Digest + Reset + Clone>(tv: TestVector) {
    let mut hasher = H::new();
    hasher.update(&tv.message);
    let mut hasher2 = hasher.clone();
    let digest = hasher.finalize();
    asserting(format!("Test Vector {}: Hashing", tv.count).as_str())
        .that(&digest.as_ref())
        .is_equal_to(tv.digest.as_slice());

    digest::Digest::reset(&mut hasher2);
    for b in tv.message {
        hasher2.update([b]);
    }
    let digest2 = hasher2.finalize();
    asserting(format!("Test Vector {}: After reset", tv.count).as_str())
        .that(&digest2.as_ref())
        .is_equal_to(tv.digest.as_slice());
}

fn run_tv_xof<X: ExtendableOutput + Default>(tv: TestVector) {
    let mut hasher = X::default();
    hasher.update(&tv.message);
    let mut reader = hasher.finalize_xof();
    let mut digest = vec![0u8; tv.digest.len()];
    reader.read(digest.as_mut_slice());
    asserting(format!("Test Vector {}: XOF", tv.count).as_str())
        .that(&digest)
        .is_equal_to(&tv.digest);

    reader.read(digest.as_mut_slice());
    asserting(format!("Test Vector {}: XOF", tv.count).as_str())
        .that(&digest)
        .is_not_equal_to(&tv.digest);
}

fn parse_tvs(tvs: &str) -> Vec<TestVector> {
    let mut fields: HashMap<String, String> = HashMap::new();
    let mut ret = Vec::new();

    for line in tvs.lines() {
        if line.is_empty() && !fields.is_empty() {
            ret.push(TestVector::new(
                &fields["Count"],
                &fields["Msg"],
                &fields["MD"],
            ));
            fields.clear();
            continue;
        }

        let mut values = line.split(" = ");
        fields.insert(
            values.next().unwrap().to_string(),
            values.next().unwrap().to_string(),
        );
    }

    asserting!("Test Vectors available")
        .that(&ret.len())
        .is_greater_than(0);
    ret
}

#[test]
fn test_vectors_asconhash() {
    let tvs = parse_tvs(include_str!("data/asconhash.txt"));
    for tv in tvs {
        run_tv::<AsconHash>(tv);
    }
}

#[test]
fn test_vectors_asconhasha() {
    let tvs = parse_tvs(include_str!("data/asconhasha.txt"));
    for tv in tvs {
        run_tv::<AsconAHash>(tv);
    }
}

#[test]
fn test_vectors_asconxof() {
    let tvs = parse_tvs(include_str!("data/asconxof.txt"));
    for tv in tvs {
        run_tv_xof::<AsconXof>(tv);
    }
}

#[test]
fn test_vectors_asconaxof() {
    let tvs = parse_tvs(include_str!("data/asconxofa.txt"));
    for tv in tvs {
        run_tv_xof::<AsconAXof>(tv);
    }
}

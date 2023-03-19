// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

use ascon_hash::{AsconAHash, AsconHash, Digest};
use criterion::{
    black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion, Throughput,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const KB: usize = 1024;

fn bench_for_size<H: Digest + Default>(b: &mut Bencher, rng: &mut dyn RngCore, size: usize) {
    let mut plaintext = vec![0u8; size];
    rng.fill_bytes(plaintext.as_mut_slice());

    b.iter(|| {
        let mut hasher = H::default();
        hasher.update(&plaintext);
        black_box(hasher.finalize())
    });
}

fn criterion_benchmark<A: Digest + Default>(c: &mut Criterion, name: &str) {
    let mut rng = StdRng::from_entropy();
    let mut group = c.benchmark_group(name);
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].into_iter() {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            bench_for_size::<A>(b, &mut rng, size)
        });
    }
    group.finish();
}

fn criterion_bench_ascon(c: &mut Criterion) {
    criterion_benchmark::<AsconHash>(c, "AsconHash");
}

fn criterion_bench_ascona(c: &mut Criterion) {
    criterion_benchmark::<AsconAHash>(c, "AsconAHash");
}

criterion_group!(bench_ascon, criterion_bench_ascon,);
criterion_group!(bench_ascona, criterion_bench_ascona,);
criterion_main!(bench_ascon, bench_ascona);

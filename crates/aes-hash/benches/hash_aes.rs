#![allow(clippy::all)]
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use swanky_aes_hash::{CorrelationRobustHash, TweakableCircularCorrelationRobustHash};
use swanky_block::Block;

fn bench_cr_hash(c: &mut Criterion) {
    c.bench_function("CorrelationRobustHash", |b| {
        let hash = CorrelationRobustHash::new(rand::random::<Block>());
        let x = rand::random::<Block>();
        b.iter(|| {
            let z = hash.hash(black_box(x));
            black_box(z)
        });
    });
}

fn bench_tccr_hash(c: &mut Criterion) {
    c.bench_function("TweakableCircularCorrelationRobustHash", |b| {
        let hash = TweakableCircularCorrelationRobustHash::new(rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<Block>();
        b.iter(|| {
            let z = hash.hash(black_box(x), black_box(i));
            black_box(z)
        });
    });
}

criterion_group! {
    name = aeshash;
    config = Criterion::default();
    targets = bench_cr_hash, bench_tccr_hash
}
criterion_main!(aeshash);

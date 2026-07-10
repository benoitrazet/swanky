use criterion::{Criterion, criterion_group, criterion_main};
use rand::{
    Rng,
    distr::{Distribution, Uniform},
};
use std::hint::black_box;
use swanky_rng::{SwankyRng, UniformIntegersUnderBound};

mod measurement {
    use criterion::measurement::WallTime;
    pub(super) type Measurement = WallTime;

    pub(super) fn new_measurement() -> Measurement {
        WallTime
    }
}

use measurement::*;

fn bench_swanky_rand(c: &mut Criterion<Measurement>) {
    c.bench_function("SwankyRng::rand", |b| {
        let mut rng = SwankyRng::new();
        let mut x = (0..16 * 1024)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| rng.fill_bytes(black_box(&mut x)));
    });
}

fn bench_swanky_rand_int_108000(c: &mut Criterion<Measurement>) {
    const BOUND: u32 = 108000;
    c.bench_function("SwankyRng::rand 32 integers under 108000", |b| {
        let mut rng = SwankyRng::new();
        let dist = Uniform::new(0, BOUND).expect("bounds finite and low < high");
        b.iter(|| {
            for _ in 0..32 {
                black_box(dist.sample(&mut rng));
            }
        });
    });
    c.bench_function(
        "SwankyRng::uniform_integers_under_bound 32 integers under 108000",
        |b| {
            let mut rng = SwankyRng::new();
            let dist = UniformIntegersUnderBound::new(BOUND);
            b.iter(|| {
                black_box(dist.sample(&mut rng));
                black_box(dist.sample(&mut rng));
            });
        },
    );
}

fn bench_swanky_rand_int_126(c: &mut Criterion<Measurement>) {
    const BOUND: u32 = 126;
    c.bench_function("SwankyRng::rand 32 integers under 126", |b| {
        let mut rng = SwankyRng::new();
        let dist = Uniform::new(0, BOUND).expect("bounds finite and low < high");
        b.iter(|| {
            for _ in 0..32 {
                black_box(dist.sample(&mut rng));
            }
        });
    });
    c.bench_function(
        "SwankyRng::uniform_integers_under_bound 32 integers under 126",
        |b| {
            let mut rng = SwankyRng::new();
            let dist = UniformIntegersUnderBound::new(BOUND);
            b.iter(|| {
                black_box(dist.sample(&mut rng));
                black_box(dist.sample(&mut rng));
            });
        },
    );
}

criterion_group! {
    name = swanky_rng;
    config = Criterion::default().with_measurement(new_measurement()).sample_size(4096);
    targets = bench_swanky_rand, bench_swanky_rand_int_126, bench_swanky_rand_int_108000
}
criterion_main!(swanky_rng);

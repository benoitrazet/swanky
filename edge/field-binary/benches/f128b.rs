use std::time::Duration;
use rand::Rng;
use criterion::{Criterion, criterion_group, criterion_main};

use swanky_field_binary::F128b;
use vectoreyes::U8x16;

fn mul(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("f128b::mul", move |b| {
        b.iter_batched(
            || {
                let x = F128b::from(rng.r#gen::<U8x16>());
                let y = F128b::from(rng.r#gen::<U8x16>());
                (x, y)
            },
            |(mut x, y)| {
                x *= y;
                std::hint::black_box(x)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn clmul(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("f128b::clmul", move |b| {
        b.iter_batched(
            || {
                let x = rng.r#gen::<u128>();
                let y = rng.r#gen::<u128>();
                (x, y)
            },
            |(x, y)| {
                let z = F128b::clmul(x, y);
                std::hint::black_box(z)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn clmul2(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("f128b::clmul2", move |b| {
        b.iter_batched(
            || {
                let x = rng.r#gen::<u128>();
                let y = rng.r#gen::<u128>();
                (x, y)
            },
            |(x, y)| {
                let z = F128b::clmul2(x, y);
                std::hint::black_box(z)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn clmul_orig(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("f128b::clmul_orig", move |b| {
        b.iter_batched(
            || {
                let x = rng.r#gen::<u128>();
                let y = rng.r#gen::<u128>();
                (x, y)
            },
            |(x, y)| {
                let z = F128b::clmul_orig(x, y);
                std::hint::black_box(z)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn reduce(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("f128b::reduce", move |b| {
        b.iter_batched(
            || {
                let x = rng.r#gen::<u128>();
                let y = rng.r#gen::<u128>();
                (x, y)
            },
            |(x, y)| {
                let z = F128b::reduce(x, y);
                std::hint::black_box(z)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn reduce2(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("f128b::reduce2", move |b| {
        b.iter_batched(
            || {
                let x = rng.r#gen::<u128>();
                let y = rng.r#gen::<u128>();
                (x, y)
            },
            |(x, y)| {
                let z = F128b::reduce2(x, y);
                std::hint::black_box(z)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn reduce_orig(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("f128b::reduce_orig", move |b| {
        b.iter_batched(
            || {
                let x = rng.r#gen::<u128>();
                let y = rng.r#gen::<u128>();
                (x, y)
            },
            |(x, y)| {
                let z = F128b::reduce_orig(x, y);
                std::hint::black_box(z)
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = f128b_benches;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = mul,
    clmul, clmul2, clmul_orig,
    reduce, reduce2, reduce_orig,
}

criterion_main!(f128b_benches);

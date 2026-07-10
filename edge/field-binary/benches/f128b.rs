use criterion::{Criterion, criterion_group, criterion_main};
use rand::RngExt;
use std::time::Duration;

use swanky_field_binary::F128b;
use vectoreyes::U8x16;

fn mul(c: &mut Criterion) {
    let mut rng = rand::rng();
    c.bench_function("f128b::mul", move |b| {
        b.iter_batched(
            || {
                let x = F128b::from(rng.random::<U8x16>());
                let y = F128b::from(rng.random::<U8x16>());
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

criterion_group! {
    name = f128b_benches;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = mul
}

criterion_main!(f128b_benches);

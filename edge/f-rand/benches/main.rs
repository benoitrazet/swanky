use criterion::{Criterion, criterion_group, criterion_main, measurement::WallTime};
use swanky_party::party_system;
use swanky_rng::AesRng;

party_system! {
    mod ps {
        PartyA,
        PartyB,
    }
}
use ps::{PartyA, PartyB};

fn bench_random_seed(c: &mut Criterion<WallTime>) {
    const COUNT: usize = 1000;
    let mut rng_a = AesRng::new();
    let mut rng_b = AesRng::new();
    c.bench_function(&format!("random_seed::{COUNT}"), |b| {
        b.iter(|| {
            swanky_channel::local::local_channel_pair(
                |c| {
                    for _ in 0..COUNT {
                        swanky_f_rand::random_seed::<PartyA, _>(c, &mut rng_a)?;
                    }
                    Ok(())
                },
                |c| {
                    for _ in 0..COUNT {
                        swanky_f_rand::random_seed::<PartyB, _>(c, &mut rng_b)?;
                    }
                    Ok(())
                },
            )
            .unwrap();
        });
    });
}

criterion_group! {
    name = random_seed;
    config = Criterion::default();
    targets = bench_random_seed
}
criterion_main!(random_seed);

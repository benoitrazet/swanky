//! Private set intersection (PSTY) benchmarks using `criterion`.

use criterion::{Criterion, criterion_group, criterion_main};
use popsicle::psty::{Receiver, Sender};
use std::time::Duration;
use swanky_rng::AesRng;

const SIZE: usize = 15;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(SIZE)).collect()
}

fn bench_psty_init() {
    swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = AesRng::new();
            let _ = Sender::init(channel, &mut rng).unwrap();
            Ok(())
        },
        |channel| {
            let mut rng = AesRng::new();
            let _ = Receiver::init(channel, &mut rng).unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn bench_psty(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) {
    swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = AesRng::new();
            let mut p1 = Sender::init(channel, &mut rng).unwrap();
            p1.send(&inputs1, channel, &mut rng).unwrap();
            Ok(())
        },
        |channel| {
            let mut rng = AesRng::new();
            let mut p2 = Receiver::init(channel, &mut rng).unwrap();
            p2.receive(&inputs2, channel, &mut rng).unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn bench_psi(c: &mut Criterion) {
    c.bench_function("psi::PSTY (initialization)", move |bench| {
        bench.iter(|| {
            bench_psty_init();
            std::hint::black_box(())
        })
    });
    c.bench_function("psi::PSTY (n = 2^8)", move |bench| {
        let rs = rand_vec_vec(1 << 8);
        bench.iter(|| {
            bench_psty(rs.clone(), rs.clone());
            std::hint::black_box(())
        })
    });
    c.bench_function("psi::PSTY (n = 2^12)", move |bench| {
        let rs = rand_vec_vec(1 << 12);
        bench.iter(|| {
            bench_psty(rs.clone(), rs.clone());
            std::hint::black_box(())
        })
    });
    c.bench_function("psi::PSTY (n = 2^16)", move |bench| {
        let rs = rand_vec_vec(1 << 16);
        bench.iter(|| {
            bench_psty(rs.clone(), rs.clone());
            std::hint::black_box(())
        })
    });
    // c.bench_function("psi::PSTY (n = 2^20)", move |bench| {
    //     let rs = rand_vec_vec(1 << 20);
    //     bench.iter(|| {
    //         let v = bench_psty(rs.clone(), rs.clone());
    //         std::hint::black_box(v)
    //     })
    // });
}

criterion_group! {
    name = psi;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_psi
}

criterion_main!(psi);

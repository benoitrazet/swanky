#![allow(clippy::all)]
//! Private set intersection (PSTY) benchmarks using `criterion`.

use criterion::{Criterion, criterion_group, criterion_main};
use popsicle::psty_payload::{Receiver, Sender};
use swanky_aes_rng::AesRng;
use swanky_block::Block512;
use swanky_channel_legacy::Channel;

use rand::{CryptoRng, Rng};

use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
    time::Duration,
};

const SIZE: usize = 15;

fn rand_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(size: usize) -> Vec<Vec<u8>> {
    (0..size).map(|_| rand_vec(SIZE)).collect()
}

fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
    values
        .into_iter()
        .map(|item| {
            let value_bytes = item.to_le_bytes();
            let mut res_block = [0 as u8; 64];
            for i in 0..8 {
                res_block[i] = value_bytes[i];
            }
            Block512::from(res_block)
        })
        .collect()
}
fn rand_u64_vec<RNG: CryptoRng + Rng>(n: usize, modulus: u64, rng: &mut RNG) -> Vec<u64> {
    (0..n).map(|_| rng.r#gen::<u64>() % modulus).collect()
}

fn bench_psty_payload_init() {
    let (sender, receiver) = UnixStream::pair().unwrap();

    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let _ = Sender::init(&mut channel, &mut rng).unwrap();
    });

    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let _ = Receiver::init(&mut channel, &mut rng).unwrap();

    handle.join().unwrap();
}

fn bench_psty_payload(
    sender_inputs: Vec<Vec<u8>>,
    receiver_inputs: Vec<Vec<u8>>,
    payloads: Vec<Block512>,
    weights: Vec<Block512>,
) -> () {
    let (sender, receiver) = UnixStream::pair().unwrap();

    std::thread::spawn(move || {
        let mut rng = AesRng::new();

        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);

        let mut psi = Sender::init(&mut channel, &mut rng).unwrap();

        // For small to medium sized sets where batching can occur accross all bins
        let _ = psi
            .full_protocol(&sender_inputs, &weights, &mut channel, &mut rng)
            .unwrap();
    });

    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
    // For small to medium sized sets where batching can occur accross all bins
    let _ = psi
        .full_protocol(&receiver_inputs, &payloads, &mut channel, &mut rng)
        .unwrap();
}

fn bench_psi(c: &mut Criterion) {
    c.bench_function("psi::PSTY PAYLOAD (initialization)", move |bench| {
        bench.iter(|| {
            let result = bench_psty_payload_init();
            std::hint::black_box(result)
        })
    });
    c.bench_function("psi::PSTY PAYLOAD (n = 2^8)", move |bench| {
        let mut rng = AesRng::new();
        let rs = rand_vec_vec(1 << 8);
        let payload = int_vec_block512(rand_u64_vec(1 << 8, 1 << 30, &mut rng));
        bench.iter(|| {
            let v = bench_psty_payload(rs.clone(), rs.clone(), payload.clone(), payload.clone());
            std::hint::black_box(v)
        })
    });
    c.bench_function("psi::PSTY PAYLOAD (n = 2^12)", move |bench| {
        let mut rng = AesRng::new();
        let rs = rand_vec_vec(1 << 12);
        let payload = int_vec_block512(rand_u64_vec(1 << 12, 1 << 30, &mut rng));
        bench.iter(|| {
            let v = bench_psty_payload(rs.clone(), rs.clone(), payload.clone(), payload.clone());
            std::hint::black_box(v)
        })
    });
}

criterion_group! {
    name = psi;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_psi
}

criterion_main!(psi);

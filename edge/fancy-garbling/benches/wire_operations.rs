use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{AllWire, WireLabel, util::RngExt};
use std::time::Duration;
use swanky_aes_rng::AesRng;
use vectoreyes::U8x16;

fn bench_digits(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::digits ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = U8x16::from(rng.gen_u128());
        let w = AllWire::from_repr(x, p);
        b.iter(|| {
            let digits = w.digits();
            std::hint::black_box(digits);
        });
    });
}

fn bench_unpack(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::from_block ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = rng.gen_usable_block(p);
        b.iter(|| {
            let w = AllWire::from_repr(x, p);
            std::hint::black_box(w);
        });
    });
}

fn bench_pack(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::as_block ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let w = AllWire::rand(rng, p);
        b.iter(|| {
            let x = w.to_repr();
            std::hint::black_box(x);
        });
    });
}

fn bench_plus(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::plus ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = AllWire::rand(rng, p);
        let y = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.clone() + y.clone();
            std::hint::black_box(z);
        });
    });
}

fn bench_minus(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::minus ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = AllWire::rand(rng, p);
        let y = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.clone() - y.clone();
            std::hint::black_box(z);
        });
    });
}

fn bench_cmul(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::cmul ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = AllWire::rand(rng, p);
        let c = rng.gen_u16();
        b.iter(|| {
            let z = x.clone() * c;
            std::hint::black_box(z);
        });
    });
}

fn bench_negate(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::negate ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = AllWire::rand(rng, p);
        b.iter(|| {
            let z = -x.clone();
            std::hint::black_box(z);
        });
    });
}

fn bench_hash(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::hash ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let tweak = rand::random::<u128>();
        let x = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.hash(tweak);
            std::hint::black_box(z);
        });
    });
}

fn bench_hashback(c: &mut Criterion, q: u16) {
    c.bench_function(&format!("wire::hashback ({})", q), move |b| {
        let rng = &mut rand::thread_rng();
        let tweak = rand::random::<u128>();
        let wire = AllWire::rand(rng, q);
        b.iter(|| {
            let z = wire.hashback(tweak, q);
            std::hint::black_box(z);
        });
    });
}

fn bench_zero(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::zero ({})", p), move |b| {
        b.iter(|| {
            let z = AllWire::zero(p);
            std::hint::black_box(z);
        });
    });
}

fn bench_rand(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::rand ({})", p), move |b| {
        let rng = &mut AesRng::new();
        b.iter(|| {
            let z = AllWire::rand(rng, p);
            std::hint::black_box(z);
        });
    });
}

fn bench_rand_delta(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::rand_delta ({})", p), move |b| {
        let rng = &mut AesRng::new();
        b.iter(|| {
            let z = AllWire::rand_delta(rng, p);
            std::hint::black_box(z);
        });
    });
}

fn digits(c: &mut Criterion) {
    bench_digits(c, 2);
    bench_digits(c, 3);
    bench_digits(c, 5);
    bench_digits(c, 17);
}

fn unpack(c: &mut Criterion) {
    for q in 2..33 {
        bench_unpack(c, q);
    }
    bench_unpack(c, 113);
    bench_unpack(c, 257);
}
fn pack(c: &mut Criterion) {
    bench_pack(c, 2);
    bench_pack(c, 3);
    bench_pack(c, 5);
    bench_pack(c, 17);
}
fn plus(c: &mut Criterion) {
    bench_plus(c, 2);
    bench_plus(c, 3);
    bench_plus(c, 5);
    bench_plus(c, 17);
}
fn minus(c: &mut Criterion) {
    bench_minus(c, 2);
    bench_minus(c, 3);
    bench_minus(c, 5);
    bench_minus(c, 17);
}
fn cmul(c: &mut Criterion) {
    bench_cmul(c, 2);
    bench_cmul(c, 3);
    bench_cmul(c, 5);
    bench_cmul(c, 17);
}
fn negate(c: &mut Criterion) {
    bench_negate(c, 2);
    bench_negate(c, 3);
    bench_negate(c, 5);
    bench_negate(c, 17);
}
fn hash(c: &mut Criterion) {
    bench_hash(c, 2);
    bench_hash(c, 3);
    bench_hash(c, 5);
    bench_hash(c, 17);
}
fn hashback(c: &mut Criterion) {
    bench_hashback(c, 2);
    bench_hashback(c, 3);
    bench_hashback(c, 5);
    bench_hashback(c, 17);
}
fn zero(c: &mut Criterion) {
    bench_zero(c, 2);
    bench_zero(c, 3);
    bench_zero(c, 5);
    bench_zero(c, 17);
}
fn rand(c: &mut Criterion) {
    bench_rand(c, 2);
    bench_rand(c, 3);
    bench_rand(c, 5);
    bench_rand(c, 17);
}
fn rand_delta(c: &mut Criterion) {
    bench_rand_delta(c, 2);
    bench_rand_delta(c, 3);
    bench_rand_delta(c, 5);
    bench_rand_delta(c, 17);
}

criterion_group! {
    name = wire_benches;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = digits, unpack, pack, plus, minus, cmul, negate, hash, hashback, zero, rand, rand_delta
}

criterion_main!(wire_benches);

//! Benchmark code of garbling / evaluating using Nigel's circuits.

use core::time::Duration;
use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{
    AllWire, WireMod2,
    circuits::{aes::test::TestAesNonExpanded, sha::test::TestSha256CompressionFunction},
    classic::GarbledCircuit,
};
use swanky_rng::SwankyRng;

fn bench_garble_aes_binary(c: &mut Criterion) {
    let aes = TestAesNonExpanded::new();
    c.bench_function("garble::aes-binary", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&aes, SwankyRng::new()));
    });
}

fn bench_eval_aes_binary(c: &mut Criterion) {
    let aes = TestAesNonExpanded::new();
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&aes, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0; 256]);
    let key = inputs[..128].try_into().unwrap();
    let block = inputs[128..].try_into().unwrap();
    c.bench_function("eval::aes-binary", move |bench| {
        bench.iter(|| gc.eval_to_wirelabels(&aes, &(key, block)))
    });
}

fn bench_garble_sha_256_binary(c: &mut Criterion) {
    let sha256 = TestSha256CompressionFunction::new();
    c.bench_function("garble::sha-256-binary", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&sha256, SwankyRng::new()));
    });
}

fn bench_eval_sha_256_binary(c: &mut Criterion) {
    let sha256 = TestSha256CompressionFunction::new();
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&sha256, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0; 512]);
    let block = inputs[..256].try_into().unwrap();
    let chain = inputs[256..].try_into().unwrap();
    c.bench_function("eval::sha-256-binary", move |bench| {
        bench.iter(|| gc.eval_to_wirelabels(&sha256, &(block, chain)))
    });
}

fn bench_garble_aes_arithmetic(c: &mut Criterion) {
    let aes = TestAesNonExpanded::new();
    c.bench_function("garble::aes-arithmetic", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<AllWire, _, _>(&aes, SwankyRng::new()));
    });
}

fn bench_eval_aes_arithmetic(c: &mut Criterion) {
    let aes = TestAesNonExpanded::new();
    let (en, gc, _) = GarbledCircuit::garble::<AllWire, _, _>(&aes, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0; 256]);
    let key: [_; 128] = inputs[..128].to_vec().try_into().unwrap();
    let block: [_; 128] = inputs[128..].to_vec().try_into().unwrap();

    c.bench_function("eval::aes-arithmetic", move |bench| {
        bench.iter(|| gc.eval_to_wirelabels(&aes, &(key.clone(), block.clone())))
    });
}

fn bench_garble_sha_256_arithmetic(c: &mut Criterion) {
    let sha256 = TestSha256CompressionFunction::new();
    c.bench_function("garble::sha-256-arithmetic", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<AllWire, _, _>(&sha256, SwankyRng::new()));
    });
}

fn bench_eval_sha_256_arithmetic(c: &mut Criterion) {
    let sha256 = TestSha256CompressionFunction::new();
    let (en, gc, _) = GarbledCircuit::garble::<AllWire, _, _>(&sha256, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0; 512]);
    let block: [_; 256] = inputs[..256].to_vec().try_into().unwrap();
    let chain: [_; 256] = inputs[256..].to_vec().try_into().unwrap();

    c.bench_function("eval::sha-256-arithmetic", move |bench| {
        bench.iter(|| gc.eval_to_wirelabels(&sha256, &(block.clone(), chain.clone())))
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_aes_binary, bench_garble_aes_arithmetic, bench_eval_aes_binary, bench_eval_aes_arithmetic,
              bench_garble_sha_256_binary, bench_garble_sha_256_arithmetic, bench_eval_sha_256_binary, bench_eval_sha_256_arithmetic
}

criterion_main!(parsing);

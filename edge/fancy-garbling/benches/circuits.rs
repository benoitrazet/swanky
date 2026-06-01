//! Benchmark code of garbling / evaluating using Nigel's circuits.

use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{
    AllWire, Evaluator, WireMod2,
    circuit::{BinaryCircuit, CircuitExecutor},
    classic::GarbledCircuit,
};
use std::{fs::File, io::BufReader, time::Duration};
use swanky_rng::SwankyRng;

fn circuit(fname: &str) -> BinaryCircuit {
    BinaryCircuit::parse_bristol_format(BufReader::new(File::open(fname).unwrap())).unwrap()
}

fn bench_garble_aes_binary(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("garble::aes-binary", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&circ, SwankyRng::new()));
    });
}

fn bench_eval_aes_binary(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&circ, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0u16; 256]);
    c.bench_function("eval::aes-binary", move |bench| {
        bench.iter(|| {
            gc.eval_to_wirelabels(
                &circ,
                &<BinaryCircuit as CircuitExecutor<Evaluator<_>>>::map(&circ, inputs.clone()),
            )
        })
    });
}

fn bench_garble_sha_1_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("garble::sha-1-binary", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&circ, SwankyRng::new()));
    });
}

fn bench_eval_sha_1_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&circ, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0u16; 512]);
    c.bench_function("eval::sha-1-binary", move |bench| {
        bench.iter(|| {
            gc.eval_to_wirelabels(
                &circ,
                &<BinaryCircuit as CircuitExecutor<Evaluator<_>>>::map(&circ, inputs.clone()),
            )
        })
    });
}

fn bench_garble_sha_256_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("garble::sha-256-binary", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&circ, SwankyRng::new()));
    });
}

fn bench_eval_sha_256_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&circ, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0u16; 512]);
    c.bench_function("eval::sha-256-binary", move |bench| {
        bench.iter(|| {
            gc.eval_to_wirelabels(
                &circ,
                &<BinaryCircuit as CircuitExecutor<Evaluator<_>>>::map(&circ, inputs.clone()),
            )
        })
    });
}

fn bench_garble_aes_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("garble::aes-arithmetic", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()));
    });
}

fn bench_eval_aes_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    let (en, gc, _) = GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0u16; 256]);
    c.bench_function("eval::aes-arithmetic", move |bench| {
        bench.iter(|| {
            gc.eval_to_wirelabels(
                &circ,
                &<BinaryCircuit as CircuitExecutor<Evaluator<_>>>::map(&circ, inputs.clone()),
            )
        })
    });
}

fn bench_garble_sha_1_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("garble::sha-1-arithmetic", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()));
    });
}

fn bench_eval_sha_1_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    let (en, gc, _) = GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0u16; 512]);
    c.bench_function("eval::sha-1-arithmetic", move |bench| {
        bench.iter(|| {
            gc.eval_to_wirelabels(
                &circ,
                &<BinaryCircuit as CircuitExecutor<Evaluator<_>>>::map(&circ, inputs.clone()),
            )
        })
    });
}

fn bench_garble_sha_256_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("garble::sha-256-arithmetic", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()));
    });
}

fn bench_eval_sha_256_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    let (en, gc, _) = GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0u16; 512]);
    c.bench_function("eval::sha-256-arithmetic", move |bench| {
        bench.iter(|| {
            gc.eval_to_wirelabels(
                &circ,
                &<BinaryCircuit as CircuitExecutor<Evaluator<_>>>::map(&circ, inputs.clone()),
            )
        })
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_aes_binary, bench_garble_aes_arithmetic, bench_eval_aes_binary, bench_eval_aes_arithmetic,  bench_garble_sha_1_binary,  bench_garble_sha_1_arithmetic,
    bench_eval_sha_1_binary, bench_eval_sha_1_arithmetic,  bench_garble_sha_256_binary, bench_garble_sha_256_arithmetic,  bench_eval_sha_256_binary, bench_eval_sha_256_arithmetic
}

criterion_main!(parsing);

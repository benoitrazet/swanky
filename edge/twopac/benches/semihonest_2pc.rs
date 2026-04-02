//! Benchmarks for semi-honest 2PC using `fancy-garbling`.

use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{
    Fancy, WireMod2,
    circuit::{BinaryCircuit as Circuit, EvaluableCircuit},
};
use std::{fs::File, io::BufReader, time::Duration};
use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

fn circuit(fname: &str) -> Circuit {
    Circuit::parse(BufReader::new(File::open(fname).unwrap())).unwrap()
}

fn _bench_circuit(circ: &Circuit, gb_inputs: Vec<u16>, ev_inputs: Vec<u16>) {
    let circ_ = circ.clone();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    swanky_channel::local::local_channel_pair(
        |channel| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng).unwrap();
            let mut xs = gb
                .encode_many(&gb_inputs, &vec![2; n_gb_inputs], channel)
                .unwrap();
            let ys = gb.receive_many(&vec![2; n_ev_inputs], channel).unwrap();
            xs.extend(ys);
            circ_.eval(&mut gb, &xs, channel).unwrap();
            Ok(())
        },
        |channel| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng).unwrap();
            let mut xs = ev.receive_many(&vec![2; n_gb_inputs], channel).unwrap();
            let ys = ev
                .encode_many(&ev_inputs, &vec![2; n_ev_inputs], channel)
                .unwrap();
            xs.extend(ys);
            circ.eval(&mut ev, &xs, channel).unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn bench_aes_binary(c: &mut Criterion) {
    let circ = circuit("../fancy-garbling/circuits/AES-non-expanded.txt");
    c.bench_function("twopac::semi-honest (AES-binary)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 128], vec![0u16; 128]))
    });
}

fn bench_sha_1_binary(c: &mut Criterion) {
    let circ = circuit("../fancy-garbling/circuits/sha-1.txt");
    c.bench_function("twopac::semi-honest (SHA-1-binary)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 512], vec![]))
    });
}

fn bench_sha_256_binary(c: &mut Criterion) {
    let circ = circuit("../fancy-garbling/circuits/sha-256.txt");
    c.bench_function("twopac::semi-honest (SHA-256-binary)", move |bench| {
        bench.iter(|| _bench_circuit(&circ, vec![0u16; 512], vec![]))
    });
}

criterion_group! {
    name = semihonest;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets = bench_aes_binary, bench_sha_1_binary, bench_sha_256_binary
}

criterion_main!(semihonest);

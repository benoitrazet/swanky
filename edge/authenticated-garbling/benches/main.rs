use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{
    FancyEncode,
    circuits::{
        aes::AesNonExpanded,
        binary::{TestBinaryAddition, TestBinarySubtraction},
    },
    test_circuits::{
        binary::{TestAndGateFanN, TestOrGateFanN, TestXorGateFanN},
        fancy::TestBinaryConstant,
    },
};
use rand::Rng;
use swanky_authenticated_garbling::{Evaluator, Garbler};
use swanky_rng::SwankyRng;

use crate::util::test_circuit;

mod util;

fn bench_party_construction(c: &mut Criterion) {
    let input_size: usize = 1000;
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let circuit = TestAndGateFanN(input_size);
    c.bench_function("party-construction", move |b| {
        b.iter(|| {
            swanky_channel::local::local_channel_pair(
                |c| Garbler::new(&circuit, c, &mut rng_gb),
                |c| Evaluator::new(&circuit, c, &mut rng_ev),
            )
            .unwrap();
        });
    });
}

fn bench_party_encoding_receiving(c: &mut Criterion) {
    let input_size: usize = 400;
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let circuit = TestAndGateFanN(2 * input_size);

    c.bench_function("party-encoding-receiving", move |b| {
        b.iter(|| {
            swanky_channel::local::local_channel_pair(
                |c| {
                    let mut gb = Garbler::new(&circuit, c, &mut rng_gb)?;
                    gb.encode_many(&vec![0; input_size], &vec![2; input_size], c)?;
                    gb.receive_many(&vec![2; input_size], c)?;
                    Ok(())
                },
                |c| {
                    let mut ev = Evaluator::new(&circuit, c, &mut rng_ev)?;
                    ev.receive_many(&vec![2; input_size], c)?;
                    ev.encode_many(&vec![0; input_size], &vec![2; input_size], c)?;
                    Ok(())
                },
            )
            .unwrap();
        });
    });
}

fn bench_single_and_gate(c: &mut Criterion) {
    let ninputs_gb = 1;
    let ninputs_ev = 1;
    let circuit = TestAndGateFanN(ninputs_gb + ninputs_ev);
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb).map(|_| rng_gb.r#gen::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev).map(|_| rng_ev.r#gen::<u16>() % 2).collect();
    c.bench_function(
        &format!("single-and-gate::input-sizes::({},{})", 1, 1),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, rng_gb.fork(), &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_constant_gates(c: &mut Criterion) {
    let circuit = TestBinaryConstant;
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..0).map(|_| rng_gb.r#gen::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..0).map(|_| rng_ev.r#gen::<u16>() % 2).collect();
    c.bench_function(
        &format!("test_constant_gates::input-sizes::({},{})", 0, 0),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, rng_gb.fork(), &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_and_gate_fan_n(c: &mut Criterion) {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestAndGateFanN(ninputs_gb + ninputs_ev);
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb).map(|_| rng_gb.r#gen::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev).map(|_| rng_ev.r#gen::<u16>() % 2).collect();
    c.bench_function(
        &format!("and-gate-fan-n::input-sizes::({ninputs_gb},{ninputs_ev})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, rng_gb.fork(), &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_or_gate_fan_n(c: &mut Criterion) {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestOrGateFanN(ninputs_gb + ninputs_ev);
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb).map(|_| rng_gb.r#gen::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev).map(|_| rng_ev.r#gen::<u16>() % 2).collect();
    c.bench_function(
        &format!("or-gate-fan-n::input-sizes::({ninputs_gb},{ninputs_ev})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, rng_gb.fork(), &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_xor_gate_fan_n(c: &mut Criterion) {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = TestXorGateFanN(ninputs_gb + ninputs_ev);

    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb).map(|_| rng_gb.r#gen::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev).map(|_| rng_ev.r#gen::<u16>() % 2).collect();
    c.bench_function(
        &format!("xor-gate-fan-n::input-sizes::({ninputs_gb},{ninputs_ev})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, rng_gb.fork(), &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_binary_addition(c: &mut Criterion) {
    let ninputs = 400;
    let circuit = TestBinaryAddition(ninputs);

    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs).map(|_| rng_gb.r#gen::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs).map(|_| rng_ev.r#gen::<u16>() % 2).collect();
    c.bench_function(
        &format!("binary-addition::input-sizes::({ninputs},{ninputs})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, rng_gb.fork(), &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_binary_subtraction(c: &mut Criterion) {
    let ninputs = 400;
    let circuit = TestBinarySubtraction(ninputs);

    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs).map(|_| rng_gb.r#gen::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs).map(|_| rng_ev.r#gen::<u16>() % 2).collect();
    c.bench_function(
        &format!("binary-subtraction::input-sizes::({ninputs},{ninputs})"),
        move |b| {
            b.iter(|| {
                test_circuit(&inputs_gb, &inputs_ev, rng_gb.fork(), &mut rng_ev, &circuit);
            });
        },
    );
}

fn bench_aes(c: &mut Criterion) {
    let mut rng_gb = SwankyRng::new();
    let mut rng_ev = SwankyRng::new();
    let inputs_gb = (0..128)
        .map(|_| rng_gb.r#gen::<u16>() % 2)
        .collect::<Vec<_>>();
    let inputs_ev = (0..128)
        .map(|_| rng_gb.r#gen::<u16>() % 2)
        .collect::<Vec<_>>();

    let circuit = AesNonExpanded::new();
    c.bench_function("aes", move |b| {
        b.iter(|| {
            test_circuit(&inputs_gb, &inputs_ev, rng_gb.fork(), &mut rng_ev, &circuit);
        })
    });
}

criterion_group! {
    name = authenticated_garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_party_construction, bench_party_encoding_receiving,
    bench_and_gate_fan_n, bench_binary_addition,bench_binary_subtraction,
    bench_constant_gates,bench_or_gate_fan_n,bench_single_and_gate,bench_xor_gate_fan_n,
    bench_aes
}

criterion_main!(authenticated_garbling);

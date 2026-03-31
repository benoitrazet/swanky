use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::WireMod2;
use ndarray::Array3;
use std::{hint::black_box, path::Path, time::Duration};
use swanky_garbled_nn::{NeuralNet, io::read_tests};
use swanky_rng::SwankyRng;

fn get_nn_and_test(dir: &Path) -> (NeuralNet, Array3<i64>) {
    // Set the base path to `$CARGO_MANIFEST_DIR` for CI.
    let base = env!("CARGO_MANIFEST_DIR");
    let dir = Path::new(base).join(dir);
    let nn = NeuralNet::from_dir(&dir).unwrap();
    let tests = read_tests(&dir, Some(1)).unwrap();
    (nn, tests[0].clone())
}

fn bench_garbling(c: &mut Criterion, dir: &Path, bitwidths: &[usize]) {
    let (nn, _) = get_nn_and_test(dir);

    c.bench_function(&format!("garbling::{dir:?}"), move |bench| {
        bench.iter(|| {
            let (encoder, gc, output_map) = nn
                .gc_garble_boolean::<WireMod2, _>(bitwidths, false, SwankyRng::new())
                .unwrap();
            black_box(encoder);
            black_box(gc);
            black_box(output_map);
        });
    });
}

fn bench_evaluation(c: &mut Criterion, dir: &Path, bitwidths: &[usize]) {
    let (nn, test) = get_nn_and_test(dir);
    let (encoder, gc, _) = nn
        .gc_garble_boolean::<WireMod2, _>(bitwidths, false, SwankyRng::new())
        .unwrap();
    let inputs = encoder.encode_inputs(&test, bitwidths[0]);

    c.bench_function(&format!("evaluation::{dir:?}"), move |bench| {
        bench.iter(|| {
            let outputs = nn.gc_eval_boolean(&inputs, &gc, bitwidths, false).unwrap();
            black_box(outputs);
        });
    });
}

#[allow(non_snake_case)]
fn bench_garbling_DINN_30(c: &mut Criterion) {
    bench_garbling(c, Path::new("neural_nets/DINN_30"), &[9; 3]);
}

#[allow(non_snake_case)]
fn bench_garbling_DINN_100(c: &mut Criterion) {
    bench_garbling(c, Path::new("neural_nets/DINN_100"), &[9; 3]);
}

#[allow(non_snake_case)]
fn bench_garbling_CryptoNets(c: &mut Criterion) {
    bench_garbling(c, Path::new("neural_nets/CryptoNets"), &[26; 11]);
}

#[allow(non_snake_case)]
fn bench_evaluation_DINN_30(c: &mut Criterion) {
    bench_evaluation(c, Path::new("neural_nets/DINN_30"), &[9; 3]);
}

#[allow(non_snake_case)]
fn bench_evaluation_DINN_100(c: &mut Criterion) {
    bench_evaluation(c, Path::new("neural_nets/DINN_100"), &[9; 3]);
}

#[allow(non_snake_case)]
fn bench_evaluation_CryptoNets(c: &mut Criterion) {
    bench_evaluation(c, Path::new("neural_nets/CryptoNets"), &[26; 11]);
}

criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garbling_DINN_30, bench_garbling_DINN_100, bench_garbling_CryptoNets
}

criterion_group! {
    name = evaluation;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_evaluation_DINN_30, bench_evaluation_DINN_100, bench_evaluation_CryptoNets
}

criterion_main!(garbling, evaluation);

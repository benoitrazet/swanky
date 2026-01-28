use criterion::{Criterion, criterion_group, criterion_main};

use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{
    Proof,
    circuit::load_circuit_from_strings_prover,
    circuit_validator::validate_circuit,
    vole::functionality::{VoleProver, VoleVerifier},
};

// Get a fresh transcript
fn transcript() -> Transcript {
    Transcript::new(b"basic happy test transcript")
}

fn benchmark_aes256(c: &mut Criterion) {
    let mini_circuit_bytes = include_str!("../circuits/aes_256_conv.sieve");
    let private_input_bytes = include_str!("../circuits/aes_256_conv_private.sieve");

    c.bench_function("aes256_parse", |b| {
        b.iter(|| {
            let circuit = load_circuit_from_strings_prover(mini_circuit_bytes, private_input_bytes);
            std::hint::black_box(circuit.is_ok());
        })
    });

    let circuit =
        load_circuit_from_strings_prover(mini_circuit_bytes, private_input_bytes).unwrap();
    validate_circuit(&circuit).unwrap();

    c.bench_function("aes256_prove", |b| {
        b.iter(|| {
            let rng = &mut thread_rng();
            let proof =
                Proof::<VoleProver, VoleVerifier>::prove::<_>(&circuit, &mut transcript(), rng)
                    .unwrap();
            std::hint::black_box(proof)
        })
    });

    let rng = &mut thread_rng();
    let proof =
        Proof::<VoleProver, VoleVerifier>::prove::<_>(&circuit, &mut transcript(), rng).unwrap();

    c.bench_function("aes256_verify", |b| {
        b.iter(|| {
            let verif = proof.verify(&circuit, &mut transcript());
            assert!(verif.is_ok());
            std::hint::black_box(verif.is_ok())
        })
    });
}

fn benchmark_sha256(c: &mut Criterion) {
    let mini_circuit_bytes = include_str!("../circuits/sha256_conv.sieve");
    let private_input_bytes = include_str!("../circuits/sha256_conv_private.sieve");

    c.bench_function("sha256_parse", |b| {
        b.iter(|| {
            let circuit = load_circuit_from_strings_prover(mini_circuit_bytes, private_input_bytes);
            std::hint::black_box(circuit.is_ok());
        })
    });

    let circuit =
        load_circuit_from_strings_prover(mini_circuit_bytes, private_input_bytes).unwrap();
    validate_circuit(&circuit).unwrap();

    c.bench_function("sha256_prove", |b| {
        b.iter(|| {
            let rng = &mut thread_rng();
            let proof =
                Proof::<VoleProver, VoleVerifier>::prove::<_>(&circuit, &mut transcript(), rng)
                    .unwrap();
            std::hint::black_box(proof)
        })
    });

    let rng = &mut thread_rng();
    let proof =
        Proof::<VoleProver, VoleVerifier>::prove::<_>(&circuit, &mut transcript(), rng).unwrap();

    c.bench_function("sha256_verify", |b| {
        b.iter(|| {
            let verif = proof.verify(&circuit, &mut transcript());
            assert!(verif.is_ok());
            std::hint::black_box(verif.is_ok())
        })
    });
}

criterion_group!(benches, benchmark_aes256, benchmark_sha256);
criterion_main!(benches);

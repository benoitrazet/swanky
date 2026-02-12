use fancy_garbling::util as numbers;
use ndarray::Array3;
use std::time::Instant;
use swanky_garbled_nn::Accuracy;
use swanky_garbled_nn::NeuralNet;

/// Run benchmarks on the given neural network and its associated parameters.
pub fn bench(
    nn: &NeuralNet,
    inputs: &[Array3<i64>],
    bitwidth: &[usize],
    niters: usize,
    secret_weights: bool,
    binary: bool,
    accuracy: &Accuracy,
) -> eyre::Result<()> {
    println!("* running garble/eval benchmark");

    // generate moduli for the given bitwidth
    let moduli = bitwidth
        .iter()
        .map(|&b| numbers::modulus_with_width(b as u32))
        .collect::<Vec<_>>();

    println!("* computing fancy computation info");

    if binary {
        nn.informer_binary(bitwidth, secret_weights)?;
    } else {
        nn.informer_arith(&moduli, secret_weights, accuracy)?;
    }

    println!("* benchmarking garbler streaming to evaluator");

    let total_time = Instant::now();

    for _ in 0..niters {
        if binary {
            nn.eval_roundtrip_binary(&inputs[0], bitwidth, secret_weights)?;
        } else {
            nn.eval_roundtrip_arith(&inputs[0], &moduli, secret_weights, accuracy)?;
        }
    }

    println!(
        "streaming took {:.2?} over {niters} iterations",
        total_time.elapsed()
    );

    Ok(())
}

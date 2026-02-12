use fancy_garbling::FancyInput;
use fancy_garbling::dummy::Dummy;
use fancy_garbling::informer::Informer;
use fancy_garbling::util as numbers;
use std::time::Instant;
use swanky_channel::Channel;
use swanky_garbled_nn::Accuracy;
use swanky_garbled_nn::NeuralNet;

/// Run benchmarks on the given neural network and its associated parameters.
pub fn bench(
    nn: &NeuralNet,
    bitwidth: &[usize],
    niters: usize,
    secret_weights: bool,
    binary: bool,
    accuracy: &Accuracy,
) {
    println!("* running garble/eval benchmark");

    // generate moduli for the given bitwidth
    let moduli = bitwidth
        .iter()
        .map(|&b| numbers::modulus_with_width(b as u32))
        .collect::<Vec<_>>();

    println!("* computing fancy computation info");

    ////////////////////////////////////////////////////////////////////////////////
    // run the neural network with Informer
    let mut informer = Informer::new(Dummy::new());

    if binary {
        Channel::with(std::io::empty(), |channel| {
            let inps = (0..nn.num_inputs())
                .map(|_| informer.bin_encode(0, bitwidth[0], channel).unwrap())
                .collect::<Vec<_>>();

            nn.eval_boolean(
                &mut informer,
                &inps,
                bitwidth,
                secret_weights,
                true,
                channel,
            );
            Ok(())
        })
        .unwrap();
    } else {
        Channel::with(std::io::empty(), |channel| {
            let inps = (0..nn.num_inputs())
                .map(|_| informer.crt_encode(0, moduli[0], channel).unwrap())
                .collect::<Vec<_>>();

            nn.eval_arith(
                &mut informer,
                &inps,
                &moduli,
                secret_weights,
                true,
                accuracy,
                channel,
            );
            Ok(())
        })
        .unwrap();
    }
    println!("{}", informer.stats());

    ////////////////////////////////////////////////////////////////////////////////
    // bench streaming

    println!("* benchmarking garbler streaming to evaluator");

    let total_time = Instant::now();

    for _ in 0..niters {
        nn.eval_roundtrip(bitwidth, &moduli, secret_weights, binary, accuracy);
    }

    println!(
        "streaming took {:.2?} over {niters} iterations",
        total_time.elapsed()
    );
}

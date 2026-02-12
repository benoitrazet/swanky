use clap::error::ErrorKind;
use clap::{Error, Parser, Subcommand};
use fancy_garbling::dummy::Dummy;
use ndarray::Array3;
use serde_json::{self, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::time::Instant;
use swanky_channel::Channel;
use swanky_garbled_nn::Accuracy;
use swanky_garbled_nn::NeuralNet;

/// Garbled Neural Net Experiment Launcher
///
/// Runs experiments for (fancy) garbling neural nets.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The neural network directory to use.
    ///
    /// The directory must contain the following files: `model.json`,
    /// `weights.json`, either `tests.json` or `tests.csv`, and either
    /// `labels.json` or `labels.csv`.
    dir: PathBuf,
    /// Comma separated bitwidths to use for each layer (last number is replicated).
    #[arg(short = 'w', long, default_value = "15")]
    bitwidth: String,
    /// Run in boolean mode.
    #[arg(short = 'b', long, default_value_t = false)]
    boolean: bool,
    /// Use secret weights.
    #[arg(short = 's', long, default_value_t = false)]
    secret: bool,
    /// Number of tests to run.
    #[arg(short = 'n', long)]
    ntests: Option<usize>,
    /// Accuracy of ReLU.
    #[arg(long = "relu", default_value = "100%")]
    relu_accuracy: String,
    /// Accuracy of sign.
    #[arg(long = "sign", default_value = "100%")]
    sign_accuracy: String,
    /// Accuracy of max.
    #[arg(long = "max", default_value = "100%")]
    max_accuracy: String,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate the neural net to find the maximum bitwidth needed for each layer
    Bitwidth,
    /// Evaluate the given neural net directly over i64 values
    Direct,
    /// Test the accuracy of the fancy encoding of the neural network
    Dummy,
    /// Benchmark garbling and evaluating the neural network
    Bench {
        /// Number of iterations to run
        #[arg(short, long, default_value_t = 1)]
        niters: usize,
    },
}

pub fn main() {
    let cli = Cli::parse();

    ////////////////////////////////////////////////////////////////////////////////
    // read tests, labels, and neural net from DIR

    let dir = cli.dir;
    let ntests = cli.ntests;

    let nn = NeuralNet::try_from(dir.deref()).unwrap_or_else(|e| Error::exit(&Error::from(e)));
    println!("{nn:?}");

    print!("reading tests...");
    let tests = swanky_garbled_nn::io::read_tests(&dir, ntests)
        .unwrap_or_else(|e| Error::exit(&Error::from(e)));
    println!("finished");

    let mut labels_path = dir.join(Path::new("labels.json"));
    if !labels_path.is_file() {
        labels_path = dir.join(Path::new("labels.csv"));
        if !labels_path.is_file() {
            Error::exit(&Error::raw(
                ErrorKind::InvalidValue,
                "Given directory contains neither 'labels.json' nor 'labels.csv'",
            ));
        }
    }

    print!("reading labels...");
    let labels = read_labels(&labels_path).unwrap_or_else(|e| Error::exit(&Error::from(e)));
    println!("finished");

    ////////////////////////////////////////////////////////////////////////////////
    // read global options

    let accuracy = &Accuracy {
        relu: cli.relu_accuracy,
        sign: cli.sign_accuracy,
        max: cli.max_accuracy,
    };

    ////////////////////////////////////////////////////////////////////////////////
    // compute bitwidth

    // parse bitwidth argument
    let mut bitwidth = cli
        .bitwidth
        .split(",")
        .map(|s| {
            s.trim()
                .parse::<usize>()
                .expect("bitwidth: expected number")
        })
        .collect::<Vec<_>>();

    // pad the end with the last value
    bitwidth.resize(nn.nlayers() + 1, *bitwidth.last().unwrap());

    assert!(bitwidth[0] != 0, "you need bits for the input, dude");

    // replace 0s with the previous value
    for i in 1..bitwidth.len() {
        if bitwidth[i] == 0 {
            bitwidth[i] = bitwidth[i - 1];
        }
    }

    println!("bitwidth: {:?}", bitwidth);
    println!(
        "nprimes: {:?}",
        bitwidth
            .iter()
            .map(|&w| fancy_garbling::util::primes_with_width(w as u32).len())
            .collect::<Vec<_>>()
    );

    ////////////////////////////////////////////////////////////////////////////////
    // run benches and tests

    match &cli.command {
        Some(Commands::Bitwidth) => {
            println!("* computing bitwidth for each layer");
            let nbits = Channel::with(std::io::empty(), |channel| {
                Ok(nn.max_bitwidth(&tests, channel))
            })
            .unwrap();
            for (layerno, nbits) in nbits.into_iter().enumerate() {
                println!("Layer {}: {} bits", layerno, nbits);
            }
        }
        Some(Commands::Direct) => {
            nn.plaintext_accuracy_test(&tests, &labels);
        }
        Some(Commands::Dummy) => {
            Channel::with(std::io::empty(), |channel| {
                let mut dummy = Dummy::new();
                if cli.boolean {
                    nn.boolean_accuracy_test::<_, Dummy>(
                        &mut dummy, &tests, &labels, &bitwidth, cli.secret, channel,
                    );
                } else {
                    nn.arith_accuracy_test(
                        &mut dummy, &tests, &labels, &bitwidth, cli.secret, accuracy, channel,
                    );
                }
                Ok(())
            })
            .unwrap();
        }
        Some(Commands::Bench { niters }) => {
            bench(
                &nn,
                &tests,
                &bitwidth,
                *niters,
                cli.secret,
                cli.boolean,
                accuracy,
            )
            .map_err(|e| Error::exit(&Error::raw(ErrorKind::Io, e)));
        }
        None => {
            Error::exit(&Error::raw(
                ErrorKind::DisplayHelp,
                "no command given! try \"help\"",
            ));
        }
    }
}

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
        .map(|&b| fancy_garbling::util::modulus_with_width(b as u32))
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

/// Read labels from a file.
///
/// The file's extension must be either `csv` or `json`.
fn read_labels(file: &Path) -> std::io::Result<Vec<Vec<i64>>> {
    if file.extension().is_some_and(|ext| ext == "csv") {
        let reader = BufReader::new(File::open(file)?);
        let vec = reader
            .lines()
            .map(|line| {
                let line: Result<Vec<_>, _> = line?
                    .split(",")
                    .map(|s| {
                        s.parse::<i64>().map_err(|e| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                        })
                    })
                    .collect();
                line
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(vec)
    } else if file.extension().is_some_and(|ext| ext == "json") {
        let file = File::open(file)?;
        let obj: Value = serde_json::from_reader(file)?;

        Ok(obj
            .as_array()
            .unwrap()
            .iter()
            .map(|val| {
                val.as_array()
                    .unwrap()
                    .iter()
                    .map(|val| val.as_i64().unwrap())
                    .collect()
            })
            .collect())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Unsupported filetype: \"{file:?}\"",
        ))
    }
}

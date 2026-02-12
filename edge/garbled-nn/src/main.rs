mod garbling_benches;

use clap::error::ErrorKind;
use clap::{Error, Parser, Subcommand};
use fancy_garbling::dummy::Dummy;
use ndarray::Array3;
use serde_json::{self, Value};
use std::fs::File;
use std::io::{BufRead, BufReader, Lines};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use swanky_channel::Channel;
use swanky_garbled_nn::Accuracy;
use swanky_garbled_nn::NeuralNet;

pub fn get_lines(file: &str) -> Lines<BufReader<File>> {
    let f = File::open(file).expect("file not found");
    let r = BufReader::new(f);
    r.lines()
}

pub fn value_to_array3(v: &Value) -> Array3<i64> {
    let rows = v.as_array().expect("value is not an array!");

    let data = rows
        .iter()
        .map(|cols| {
            if cols.is_array() {
                cols.as_array()
                    .unwrap()
                    .iter()
                    .map(|deps| {
                        if deps.is_array() {
                            deps.as_array()
                                .expect("expected colors!")
                                .iter()
                                .map(|val| val.as_i64().expect("expected a number!"))
                                .collect::<Vec<_>>()
                        } else {
                            vec![deps.as_i64().unwrap()]
                        }
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![vec![cols.as_i64().unwrap()]]
            }
        })
        .collect::<Vec<_>>();

    let height = data.len();
    let width = data[0].len();
    let depth = data[0][0].len();

    Array3::from_shape_vec(
        (height, width, depth),
        data.into_iter().flatten().flatten().collect(),
    )
    .expect("couldnt create array!")
}

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

    let mut tests_path = dir.join(Path::new("tests.json"));
    if !tests_path.is_file() {
        tests_path = dir.join(Path::new("tests.csv"));
        if !tests_path.is_file() {
            Error::exit(&Error::raw(
                ErrorKind::InvalidValue,
                "Given directory contains neither 'tests.json' nor 'tests.csv'",
            ));
        }
    }

    print!("reading tests...");
    let tests = read_tests(&tests_path, ntests).unwrap_or_else(|e| Error::exit(&Error::from(e)));
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
            garbling_benches::bench(
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

/// Read tests from a file.
///
/// The file's extension must be either `csv` or `json`. The second argument
/// specifies the number of tests to return; `None` means return all tests in
/// the file.
fn read_tests(file: &Path, num: Option<usize>) -> std::io::Result<Vec<Array3<i64>>> {
    if file.extension().is_some_and(|ext| ext == "csv") {
        let reader = BufReader::new(File::open(file)?);
        // Note: csv can be at most 1-dimensional, if each image gets its own line
        let iter = reader.lines().map(|line| {
            let data = line?
                .split(",")
                .map(|s| {
                    s.parse::<i64>().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })
                })
                .collect::<Result<Vec<i64>, _>>()?;
            Array3::from_shape_vec((data.len(), 1, 1), data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
        });

        if let Some(n) = num {
            iter.take(n).collect()
        } else {
            iter.collect()
        }
    } else if file.extension().is_some_and(|ext| ext == "json") {
        let file = File::open(file)?;
        let obj: Value = serde_json::from_reader(file)?;
        let iter = obj.as_array().unwrap().iter().map(value_to_array3);

        if let Some(n) = num {
            Ok(iter.take(n).collect())
        } else {
            Ok(iter.collect())
        }
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Unsupported filetype: \"{file:?}\"",
        ))
    }
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

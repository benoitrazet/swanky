use crate::{
    layer::{Accuracy, ActivationFunction, Layer},
    util,
};
use fancy_garbling::{
    AllWire, BinaryBundle, BinaryWireLabel, CrtBundle, CrtGadgets, Fancy, FancyArithmetic,
    FancyBinary, FancyInput, HasModulus, WireMod2,
    classic::{GarbledChannel, GarbledCircuit},
    dummy::Dummy,
    informer::Informer,
    util::output_tweak,
};
use ndarray::Array3;
use rand::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::{
    fs::File,
    io::{Error, ErrorKind},
    path::Path,
    time::{Duration, Instant},
};
use swanky_aes_rng::AesRng;
use swanky_block::Block;
use swanky_channel::Channel;
use swanky_ot_alsz_kos::alsz;
use swanky_twopac::semihonest::{Evaluator, Garbler};

/// Input encoder for a garbled neural network.
///
/// This is created by the garbler, and allows the evaluator to encode its
/// (plaintext) input into the appropriate input wirelabels associated with the
/// garbled neural network.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InputEncoder<W> {
    inputs: Vec<BinaryBundle<W>>,
    delta: W,
}

impl<W: BinaryWireLabel> InputEncoder<W> {
    fn new(inputs: Vec<BinaryBundle<W>>, delta: W) -> Self {
        Self { inputs, delta }
    }

    /// Encode an input into its associated wirelabels.
    pub fn encode_inputs(&self, input: &Array3<i64>, bitwidth: usize) -> Vec<BinaryBundle<W>> {
        assert_eq!(input.len(), self.inputs.len());
        self.inputs
            .iter()
            .zip(input)
            .map(|(zeros, &x)| {
                let bits = util::i64_to_twos_complement(x, bitwidth);
                BinaryBundle::new(
                    zeros
                        .wires()
                        .iter()
                        .enumerate()
                        .map(|(i, zero)| zero.plus(&self.delta.cmul(1 & (bits >> i) as u16)))
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }
}

/// Output map for a garbled neural network.
///
/// This is created by the garbler, and allows the evaluator to map its output
/// wirelabels to their associated (plaintext) outputs.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputMap {
    // The first entry is the zero wirelabel, and the second entry is the one
    // wirelabel for that bundle.
    outputs: Vec<Vec<[Block; 2]>>,
}

impl OutputMap {
    fn new<W: BinaryWireLabel>(bundles: &[BinaryBundle<W>], delta: W) -> Self {
        let mut outputs = Vec::with_capacity(bundles.len());
        for (i, zeros) in bundles.iter().enumerate() {
            let wires = zeros
                .wires()
                .iter()
                .map(|zero| {
                    [
                        zero.hash(output_tweak(i, 0)),
                        zero.plus(&delta).hash(output_tweak(i, 1)),
                    ]
                })
                .collect::<Vec<_>>();
            outputs.push(wires);
        }
        Self { outputs }
    }

    /// Decode a garbled neural network output.
    pub fn to_outputs<W: BinaryWireLabel>(
        &self,
        bundles: &[BinaryBundle<W>],
    ) -> eyre::Result<Vec<i64>> {
        let mut outputs = Vec::with_capacity(bundles.len());
        for (i, bundle) in bundles.iter().enumerate() {
            let mut bits = Vec::with_capacity(bundle.size());
            for (j, wire) in bundle.wires().iter().enumerate() {
                let mut decoded = None;
                for k in 0..2 {
                    let hashed = wire.hash(output_tweak(i, k));
                    if hashed == self.outputs[i][j][k as usize] {
                        decoded = Some(k);
                        break;
                    }
                }
                if let Some(bit) = decoded {
                    bits.push(bit);
                } else {
                    eyre::bail!("Decoding failed for wire {j} in bundle {i}");
                }
            }
            outputs.push(util::i64_from_bits(&bits));
        }
        Ok(outputs)
    }
}

/// A neural network that can be garbled.
pub struct NeuralNet {
    layers: Vec<Layer>,
}

impl std::fmt::Debug for NeuralNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "neural net info:")?;
        writeln!(f, "  input dimensions: {:?}", self.layers[0].input_dims())?;
        for layer in self.layers.iter() {
            writeln!(f, "  {:?}", layer)?;
            writeln!(f, "    inp={:?}", layer.input_dims())?;
            writeln!(f, "    out={:?}", layer.output_dims())?;
        }
        Ok(())
    }
}

/// Converts a directory into a [`NeuralNet`].
///
/// The directory must have properly formatted `model.json` and `weights.json`
/// files, otherwise an error is thrown.
///
/// # Errors
/// This returns an error if the directory does not contain a `model.json` file
/// and a `weights.json` file.
impl TryFrom<&Path> for NeuralNet {
    type Error = std::io::Error;

    fn try_from(dir: &Path) -> Result<Self, Self::Error> {
        let model_path = dir.join(Path::new("model.json"));
        if !model_path.is_file() {
            return Err(Self::Error::new(
                ErrorKind::InvalidFilename,
                "`model.json` does not exist in the given diretory",
            ));
        }

        let weights_path = dir.join(Path::new("weights.json"));
        if !weights_path.is_file() {
            return Err(Self::Error::new(
                ErrorKind::InvalidFilename,
                "`weights.json` does not exist in the given diretory",
            ));
        }

        NeuralNet::from_json(model_path.to_str().unwrap(), weights_path.to_str().unwrap())
    }
}

impl NeuralNet {
    /// The number of inputs to the first layer of the neural network.
    pub fn ninputs(&self) -> usize {
        self.layers[0].input_size()
    }

    /// The number of layers in the neural network.
    pub fn nlayers(&self) -> usize {
        self.layers.len()
    }

    /// Encode an input so it can be evaluated by a boolean [`NeuralNet`].
    pub fn encode_input_boolean<
        W: HasModulus + Clone,
        F: Fancy<Item = W> + FancyInput<Item = W>,
    >(
        f: &mut F,
        input: &Array3<i64>,
        first_layer_bitwidth: usize,
        channel: &mut Channel,
    ) -> eyre::Result<Vec<BinaryBundle<W>>> {
        input
            .iter()
            .map(|&x| {
                let bits = util::i64_to_twos_complement(x, first_layer_bitwidth);
                f.bin_encode(bits, first_layer_bitwidth, channel)
            })
            .collect()
    }

    /// Receive an input so it can be evaluated by a boolean [`NeuralNet`].
    pub fn receive_input_boolean<
        W: HasModulus + Clone,
        F: Fancy<Item = W> + FancyInput<Item = W>,
    >(
        f: &mut F,
        input: &Array3<i64>,
        first_layer_bitwidth: usize,
        channel: &mut Channel,
    ) -> eyre::Result<Vec<BinaryBundle<W>>> {
        input
            .iter()
            .map(|_| f.bin_receive(first_layer_bitwidth, channel))
            .collect()
    }

    /// Encode an input so it can be evaluated by an arithmetic [`NeuralNet`].
    pub fn encode_input_arith<W: HasModulus + Clone, F: Fancy<Item = W> + FancyInput<Item = W>>(
        f: &mut F,
        input: &Array3<i64>,
        modulus: u128,
        channel: &mut Channel,
    ) -> eyre::Result<Vec<CrtBundle<W>>> {
        input
            .iter()
            .map(|&x| f.crt_encode(util::to_mod_q(x, modulus), modulus, channel))
            .collect()
    }

    /// Receive an input so it can be evaluated by an arithmetic [`NeuralNet`].
    pub fn receive_input_arith<W: HasModulus + Clone, F: Fancy<Item = W> + FancyInput<Item = W>>(
        f: &mut F,
        input: &Array3<i64>,
        modulus: u128,
        channel: &mut Channel,
    ) -> eyre::Result<Vec<CrtBundle<W>>> {
        input
            .iter()
            .map(|_| f.crt_receive(modulus, channel))
            .collect()
    }

    /// Decode a boolean output of a [`NeuralNet`] evaluation.
    pub fn decode_output_boolean<W: HasModulus + Clone, F: Fancy<Item = W>>(
        f: &mut F,
        output: &[BinaryBundle<W>],
        channel: &mut Channel,
    ) -> eyre::Result<Option<Vec<i64>>> {
        let mut result = Vec::with_capacity(output.len());
        for out in output.iter() {
            let vals = out
                .iter()
                .map(|v| f.output(v, channel))
                .collect::<eyre::Result<Vec<_>>>()?;
            let vals = vals.into_iter().collect::<Option<Vec<_>>>();
            let val = vals.map(|vals| util::i64_from_bits(&vals));
            result.push(val);
        }
        // We need to do the conversion from `Vec<Option>` to `Option<Vec>`
        // _after_ we construct the vector in its entirety, because otherwise
        // it'll short-circuit the execution, causing the garbler to exit out on
        // the first `None`.
        Ok(result.into_iter().collect::<Option<_>>())
    }

    /// Decode an arithmetic output of a [`NeuralNet`] evaluation.
    pub fn decode_output_arith<W: HasModulus + Clone, F: Fancy<Item = W>>(
        f: &mut F,
        output: &[CrtBundle<W>],
        modulus: u128,
        channel: &mut Channel,
    ) -> eyre::Result<Option<Vec<i64>>> {
        let mut result = Vec::with_capacity(output.len());
        for out in output.iter() {
            let vals = out
                .iter()
                .map(|v| f.output(v, channel))
                .collect::<eyre::Result<Vec<_>>>()?;
            let vals = vals.into_iter().collect::<Option<Vec<_>>>();
            let val = vals.map(|vals| util::from_mod_q_crt(&vals, modulus));
            result.push(val);
        }
        // We need to do the conversion from `Vec<Option>` to `Option<Vec>`
        // _after_ we construct the vector in its entirety, because otherwise
        // it'll short-circuit the execution, causing the garbler to exit out on
        // the first `None`.
        Ok(result.into_iter().collect::<Option<_>>())
    }

    /// Evaluate [`NeuralNet`] as an arithmetic garbled circuit.
    ///
    /// # Panics
    /// Panics if `moduli.len()` is not equal to `self.nlayers() + 1`, or if
    /// `circuit_inputs` does not match the dimensions of the input layer.
    #[allow(clippy::too_many_arguments)]
    pub fn eval_arith<W, F>(
        &self,
        f: &mut F,
        circuit_inputs: &[CrtBundle<W>],
        moduli: &[u128], // CRT moduli for each layer's operations
        secret_weights: bool,
        secret_weights_owned: bool,
        accuracy: &Accuracy,
        channel: &mut Channel,
    ) -> Vec<CrtBundle<W>>
    where
        W: HasModulus + Clone,
        F: Fancy<Item = W>
            + FancyInput<Item = W>
            + FancyArithmetic<Item = W>
            + CrtGadgets<Item = W>,
    {
        assert_eq!(
            moduli.len(),
            self.nlayers() + 1,
            "moduli for each layer and output required"
        );

        // Map the user-provided inputs to the input layer dimensions.
        //
        // Note: This panics if the user-provided inputs are not of the right dimension!
        let mut acc =
            Array3::from_shape_vec(self.layers[0].input_dims(), circuit_inputs.to_vec()).unwrap();
        // Evaluate the neural net layer-by-layer.
        for (i, layer) in self.layers.iter().enumerate() {
            let inp_mod = moduli[i];
            let out_mod = moduli[i + 1];
            acc = layer.as_arith(
                f,
                inp_mod,
                out_mod,
                &acc,
                secret_weights,
                secret_weights_owned,
                accuracy,
                channel,
            );
        }
        acc.into_raw_vec()
    }

    /// Evaluate [`NeuralNet`] as a boolean garbled circuit.
    ///
    /// # Panics
    /// This panics if `bitwidth.len()` does not equal `self.nlayers() + 1`, or
    /// if `circuit_inputs` does not match the dimensions of the input layer.
    pub fn eval_boolean<W, F>(
        &self,
        f: &mut F,
        circuit_inputs: &[BinaryBundle<W>],
        bitwidth: &[usize],
        secret_weights: bool,
        secret_weights_owned: bool,
        channel: &mut Channel,
    ) -> Vec<BinaryBundle<W>>
    where
        W: Clone + HasModulus,
        F: Fancy<Item = W> + FancyInput<Item = W> + FancyBinary<Item = W>,
    {
        assert_eq!(
            bitwidth.len(),
            self.nlayers() + 1,
            "`bitwidth.len()` must equal `self.nlayers() + 1`"
        );

        // Map the user-provided inputs to the input layer dimensions.
        //
        // Note: This panics if the user-provided inputs are not of the right dimension!
        let mut acc =
            Array3::from_shape_vec(self.layers[0].input_dims(), circuit_inputs.to_vec()).unwrap();
        // Evaluate the neural net layer-by-layer.
        for (i, layer) in self.layers.iter().enumerate() {
            acc = layer.as_binary(
                f,
                bitwidth[i],
                &acc,
                secret_weights,
                secret_weights_owned,
                channel,
            );
        }
        acc.iter().cloned().collect()
    }

    /// The max number of bits necessary for a value on any wire for each layer.
    pub fn max_bitwidth(&self, inputs: &[Array3<i64>], channel: &mut Channel) -> Vec<usize> {
        let mut max_nbits: Vec<usize> = vec![0; self.layers.len()];

        for (i, input) in inputs.iter().enumerate() {
            // TODO: Remove this `println`, use some logging infrastructure instead?
            println!("Current bitwidth ({}): {max_nbits:?}", i + 1);

            let mut input = input.clone();
            for (j, layer) in self.layers.iter().enumerate() {
                let (output, new_max_val) = layer.max_bitwidth(&input, channel);

                let nbits = if new_max_val < 0 {
                    (1.0 + ((-new_max_val) as f64).log2().ceil()) as usize
                } else {
                    (new_max_val as f64).log2().ceil() as usize
                };

                if nbits > max_nbits[j] {
                    max_nbits[j] = nbits;
                }

                input = output;
            }
        }

        max_nbits
    }

    /// Evaluate [`NeuralNet`] over `i64` values.
    pub fn eval_plaintext(&self, input: &Array3<i64>) -> Array3<i64> {
        Channel::with(std::io::empty(), |channel| {
            Ok(self.layers.iter().fold(input.clone(), |acc, layer| {
                layer.as_plaintext(&acc, channel)
            }))
        })
        .unwrap()
    }

    /// Read a [`NeuralNet`] from model and weights files containing data in
    /// tensorflow JSON output.
    pub fn from_json(model_filename: &str, weights_filename: &str) -> Result<Self, Error> {
        let file = File::open(model_filename)
            .unwrap_or_else(|_| panic!("couldn't open file: {}", model_filename));
        let obj: Value = serde_json::from_reader(file)?;
        let obj = obj
            .as_object()
            .expect("root value in model.json is not an object");
        let layers_obj = if obj["config"].is_array() {
            &obj["config"]
        } else {
            &obj["config"]
                .as_object()
                .expect("base config is not an object!")["layers"]
        };
        let layer_objs = layers_obj
            .as_array()
            .expect("layers is not an array")
            .iter()
            .map(|c| c.as_object().unwrap());

        let file = File::open(weights_filename)?;
        let obj: Value = serde_json::from_reader(file)?;
        let mut weights_iter = obj.as_array().unwrap().chunks(2);

        let mut layers: Vec<Layer> = Vec::new();

        for layer in layer_objs {
            let cfg = layer["config"].as_object().unwrap();
            let input_shape = input_shape(cfg, &layers);

            match layer["class_name"].as_str().unwrap() {
                "Dense" => {
                    let weights_and_biases =
                        weights_iter.next().expect("not enough weights and biases!");
                    let num_neurons = cfg["units"].as_u64().unwrap() as usize;
                    let mut weights = vec![Array3::from_elem(input_shape, Some(0)); num_neurons];

                    // keras outputs the weights in the transposition of what we need
                    let data_arr = weights_and_biases[0].as_array().unwrap();
                    assert_eq!(data_arr.len(), input_shape.0);

                    let data = data_arr.iter().map(|v| {
                        v.as_array()
                            .unwrap_or_else(|| panic!("not an array: {}", v))
                            .iter()
                            .map(|v| {
                                v.as_i64()
                                    .unwrap_or_else(|| panic!("non-integer in weights.json: {}", v))
                            })
                    });

                    for (inp_num, data_iter) in data.enumerate() {
                        for (neuron_num, val) in data_iter.enumerate() {
                            weights[neuron_num][(inp_num, 0, 0)] = Some(val);
                        }
                    }

                    let activation =
                        ActivationFunction::try_from(cfg["activation"].as_str().unwrap())?;
                    let biases = weights_and_biases[1]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|n| Some(n.as_i64().unwrap()))
                        .collect::<Vec<_>>();
                    layers.push(Layer::Dense {
                        weights,
                        biases,
                        activation,
                    });
                }

                "Dropout" => continue,

                "Conv2D" => {
                    let padding = cfg["padding"].as_str().unwrap();
                    let pad = padding == "same";

                    let activation =
                        ActivationFunction::try_from(cfg["activation"].as_str().unwrap())?;
                    let weights_and_biases =
                        weights_iter.next().expect("not enough weights and biases!");

                    let kernel_size = cfg["kernel_size"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_i64().unwrap() as usize)
                        .collect::<Vec<_>>();
                    let kernel_shape = (kernel_size[0], kernel_size[1], input_shape.2);

                    let stride = cfg["strides"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_i64().unwrap() as usize)
                        .collect::<Vec<_>>();
                    let stride = (stride[0], stride[1]);

                    let weights = weights_and_biases[0]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| {
                            v.as_array()
                                .unwrap()
                                .iter()
                                .map(|v| {
                                    v.as_array()
                                        .unwrap()
                                        .iter()
                                        .map(|v| {
                                            v.as_array()
                                                .unwrap()
                                                .iter()
                                                .map(|v| {
                                                    v.as_i64().unwrap_or_else(|| {
                                                        panic!(
                                                            "reading weights: {} not an integer",
                                                            v
                                                        )
                                                    })
                                                })
                                                .collect::<Vec<_>>()
                                        })
                                        .collect::<Vec<_>>()
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();

                    let nfilters = cfg["filters"].as_u64().unwrap() as usize;
                    let mut filters = vec![Array3::from_elem(kernel_shape, Some(0)); nfilters];

                    assert_eq!(weights.len(), kernel_shape.0);

                    for (x, weights) in weights.into_iter().enumerate() {
                        assert_eq!(weights.len(), kernel_shape.1);

                        for (y, weights) in weights.into_iter().enumerate() {
                            assert_eq!(weights.len(), kernel_shape.2);

                            for (z, weights) in weights.into_iter().enumerate() {
                                assert_eq!(weights.len(), nfilters);

                                for (filter_num, val) in weights.into_iter().enumerate() {
                                    filters[filter_num][(x, y, z)] = Some(val);
                                }
                            }
                        }
                    }

                    let biases = weights_and_biases[1]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|n| Some(n.as_i64().unwrap()))
                        .collect::<Vec<_>>();

                    assert_eq!(biases.len(), nfilters);

                    layers.push(Layer::Convolutional {
                        filters,
                        biases,
                        input_shape,
                        kernel_shape,
                        stride,
                        activation,
                        pad,
                    });
                }

                "MaxPooling2D" => {
                    let padding = cfg["padding"].as_str().unwrap();

                    let pad = padding == "same";

                    let stride = cfg["strides"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_i64().unwrap() as usize)
                        .collect::<Vec<_>>();
                    let stride = (stride[0], stride[1]);

                    let size = cfg["pool_size"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_i64().unwrap() as usize)
                        .collect::<Vec<_>>();
                    let size = (size[0], size[1]);

                    layers.push(Layer::MaxPooling2D {
                        input_shape,
                        stride,
                        size,
                        pad,
                    });
                }

                "Flatten" => {
                    let (height, width, depth) = input_shape;

                    layers.push(Layer::Flatten {
                        input_shape,
                        output_shape: (height * width * depth, 1, 1),
                    });
                }

                "Activation" => {
                    let activation =
                        ActivationFunction::try_from(cfg["activation"].as_str().unwrap())?;
                    layers.push(Layer::Activation {
                        input_shape,
                        activation,
                    });
                }

                ty => panic!("unsupported layer type \"{}\"", ty),
            }
        }

        Ok(NeuralNet { layers })
    }

    /// Evaluate [`NeuralNet`] between a boolean [`Garbler`] and [`Evaluator`].
    pub fn eval_roundtrip_binary(
        &self,
        input: &Array3<i64>,
        bitwidths: &[usize],
        secret_weights: bool,
    ) -> eyre::Result<Vec<i64>> {
        assert_eq!(input.len(), self.ninputs());
        let (_, outputs) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut garbler: Garbler<_, alsz::Sender, WireMod2> =
                    Garbler::new(channel, AesRng::new())?;
                let inputs =
                    NeuralNet::encode_input_boolean(&mut garbler, input, bitwidths[0], channel)?;
                let outputs = self.eval_boolean(
                    &mut garbler,
                    &inputs,
                    bitwidths,
                    secret_weights,
                    true,
                    channel,
                );
                let outputs = NeuralNet::decode_output_boolean(&mut garbler, &outputs, channel)?;
                // The garbler receives no outputs.
                assert_eq!(outputs, None);
                Ok(())
            },
            |channel| {
                let mut evaluator: Evaluator<AesRng, alsz::Receiver, WireMod2> =
                    Evaluator::new(channel, AesRng::new())?;
                let inputs =
                    NeuralNet::receive_input_boolean(&mut evaluator, input, bitwidths[0], channel)?;
                let outputs = self.eval_boolean(
                    &mut evaluator,
                    &inputs,
                    bitwidths,
                    secret_weights,
                    false,
                    channel,
                );
                let outputs = NeuralNet::decode_output_boolean(&mut evaluator, &outputs, channel)?;
                // The evaluator receives the outputs, so the `unwrap` should
                // never fail here.
                Ok(outputs.unwrap())
            },
        )?;
        Ok(outputs)
    }

    /// Evaluate [`NeuralNet`] between an arithmetic [`Garbler`] and [`Evaluator`].
    pub fn eval_roundtrip_arith(
        &self,
        input: &Array3<i64>,
        moduli: &[u128],
        secret_weights: bool,
        accuracy: &Accuracy,
    ) -> eyre::Result<Vec<i64>> {
        assert_eq!(input.len(), self.ninputs());
        let (_, outputs) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut gb: Garbler<_, alsz::Sender, AllWire> =
                    Garbler::new(channel, AesRng::new())?;
                let inps = NeuralNet::encode_input_arith(
                    &mut gb,
                    input,
                    *moduli.first().unwrap(),
                    channel,
                )?;
                let outputs = self.eval_arith::<_, _>(
                    &mut gb,
                    &inps,
                    moduli,
                    secret_weights,
                    true,
                    accuracy,
                    channel,
                );
                let outputs = NeuralNet::decode_output_arith(
                    &mut gb,
                    &outputs,
                    *moduli.last().unwrap(),
                    channel,
                )?;
                // The garbler receives no outputs.
                assert_eq!(outputs, None);
                Ok(())
            },
            |channel| {
                let mut ev: Evaluator<AesRng, alsz::Receiver, AllWire> =
                    Evaluator::new(channel, AesRng::new())?;
                let inps = NeuralNet::receive_input_arith(
                    &mut ev,
                    input,
                    *moduli.first().unwrap(),
                    channel,
                )?;
                let outputs = self.eval_arith::<_, _>(
                    &mut ev,
                    &inps,
                    moduli,
                    secret_weights,
                    false,
                    accuracy,
                    channel,
                );
                let outputs = NeuralNet::decode_output_arith(
                    &mut ev,
                    &outputs,
                    *moduli.last().unwrap(),
                    channel,
                )?;
                // The evaluator receives the outputs, so the `unwrap` should
                // never fail here.
                Ok(outputs.unwrap())
            },
        )?;
        Ok(outputs)
    }

    /// Output a boolean garbling of [`NeuralNet`].
    pub fn gc_garble_boolean<W: BinaryWireLabel, RNG: CryptoRng + RngCore>(
        &self,
        bitwidths: &[usize],
        secret_weights: bool,
        rng: RNG,
    ) -> eyre::Result<(InputEncoder<W>, GarbledCircuit, OutputMap)> {
        let mut channel = GarbledChannel::new_writer(None);
        let (inputs, outputs, delta) = Channel::with(&mut channel, |channel| {
            let mut garbler = fancy_garbling::Garbler::<_, W>::new(rng, channel)?;

            // Construct the zero wires for the input.
            let inputs = (0..self.ninputs())
                .map(|_| {
                    let (zeros, _) = garbler.bin_encode_wire(0, bitwidths[0]);
                    zeros
                })
                .collect::<Vec<_>>();

            // Evaluate the neural network to derive the zero wires for the output.
            let outputs = self.eval_boolean(
                &mut garbler,
                &inputs,
                bitwidths,
                secret_weights,
                true,
                channel,
            );

            let delta = garbler.delta(2);
            Ok((inputs, outputs, delta))
        })?;
        let encoder = InputEncoder::new(inputs, delta);
        let gc = GarbledCircuit::new(channel.finish_writing());
        let output_map = OutputMap::new(&outputs, delta);
        Ok((encoder, gc, output_map))
    }

    /// Evaluate a boolean garbling of [`NeuralNet`].
    ///
    /// The inputs are provided as (bundles of) wirelabels, and the output is a
    /// vector of (bundles of) wirelabels corresponding to the output.
    pub fn gc_eval_boolean<W: BinaryWireLabel>(
        &self,
        inputs: &[BinaryBundle<W>],
        gc: &GarbledCircuit,
        bitwidth: &[usize],
        secret_weights: bool,
    ) -> eyre::Result<Vec<BinaryBundle<W>>> {
        // Evaluate the garbled circuit on the input wirelabels.
        Channel::with(GarbledChannel::from(gc), |channel| {
            let mut evaluator = fancy_garbling::Evaluator::<W>::new(channel)?;

            let outputs = self.eval_boolean(
                &mut evaluator,
                inputs,
                bitwidth,
                secret_weights,
                false,
                channel,
            );
            Ok(outputs)
        })
    }

    // TODO: The `*_accuracy_test` methods have _a lot_ of commonalities. Can we
    // combine them in some way?

    /// Evaluate the [`NeuralNet`] over all the provided boolean inputs and
    /// track the accuracy of the evaluations.
    pub fn boolean_accuracy_test<W, F>(
        &self,
        f: &mut F,
        images: &[Array3<i64>],
        labels: &[Vec<i64>],
        bitwidth: &[usize],
        secret_weights: bool,
        channel: &mut Channel,
    ) where
        W: Clone + HasModulus,
        F: Fancy<Item = W> + FancyInput<Item = W> + FancyBinary<Item = W>,
    {
        let mut errors = 0;

        let first_layer_nbits = *bitwidth.first().unwrap();

        let total_time = Instant::now();

        for (img_num, img) in images.iter().enumerate() {
            println!(
                "(avg {:.2?}) [{} errors ({:.2}%)] ",
                if img_num > 0 {
                    total_time.elapsed() / img_num as u32
                } else {
                    Duration::ZERO
                },
                errors,
                100.0 * (1.0 - errors as f32 / img_num as f32)
            );

            let inp = NeuralNet::encode_input_boolean(f, img, first_layer_nbits, channel).unwrap();
            let outs = self.eval_boolean(f, &inp, bitwidth, secret_weights, true, channel);
            let res = NeuralNet::decode_output_boolean(f, &outs, channel)
                .unwrap()
                .unwrap();

            if util::index_of_max(&res) != util::index_of_max(&labels[img_num]) {
                errors += 1;
            }
        }

        println!(
            "errors: {}/{}. accuracy: {:.2}%",
            errors,
            images.len(),
            100.0 * (1.0 - errors as f32 / images.len() as f32)
        );
    }

    /// Evaluate the [`NeuralNet`] over all the provided arithmetic inputs and
    /// track the accuracy of the evaluations.
    #[allow(clippy::too_many_arguments)]
    pub fn arith_accuracy_test<W, F>(
        &self,
        f: &mut F,
        images: &[Array3<i64>],
        labels: &[Vec<i64>],
        bitwidth: &[usize],
        secret_weights: bool,
        accuracy: &Accuracy,
        channel: &mut Channel,
    ) where
        W: Clone + HasModulus,
        F: Fancy<Item = W> + FancyInput<Item = W> + FancyArithmetic<Item = W> + CrtGadgets,
    {
        let moduli = util::bitwidths_to_moduli(bitwidth);

        let qfirst = *moduli.first().unwrap();
        let qlast = *moduli.last().unwrap();

        let mut errors = 0;
        let total_time = Instant::now();

        for (img_num, img) in images.iter().enumerate() {
            println!(
                "(avg {:?}) [{} errors ({:.2}%)] ",
                if img_num > 0 {
                    total_time.elapsed() / img_num as u32
                } else {
                    Duration::ZERO
                },
                errors,
                100.0 * (1.0 - errors as f32 / img_num as f32)
            );

            let inp = NeuralNet::encode_input_arith(f, img, qfirst, channel).unwrap();
            let outs = self.eval_arith(f, &inp, &moduli, secret_weights, true, accuracy, channel);
            let res = NeuralNet::decode_output_arith(f, &outs, qlast, channel)
                .unwrap()
                .unwrap();

            if util::index_of_max(&res) != util::index_of_max(&labels[img_num]) {
                errors += 1;
            }
        }

        println!(
            "errors: {}/{}. accuracy: {:.2}%",
            errors,
            images.len(),
            100.0 * (1.0 - errors as f32 / images.len() as f32)
        );
    }

    /// Evaluate the [`NeuralNet`] in plaintext.
    pub fn plaintext_accuracy_test(&self, inputs: &[Array3<i64>], labels: &[Vec<i64>]) {
        let mut errors = 0;
        let total_time = Instant::now();

        for (img_num, (img, label)) in inputs.iter().zip(labels.iter()).enumerate() {
            println!(
                "(avg {:.2?}) [{} errors ({:.2}%)] ",
                if img_num > 0 {
                    total_time.elapsed() / img_num as u32
                } else {
                    Duration::ZERO
                },
                errors,
                100.0 * (1.0 - errors as f32 / img_num as f32)
            );

            let res = self.eval_plaintext(img).into_iter().collect::<Vec<_>>();

            if util::index_of_max(&res) != util::index_of_max(label) {
                errors += 1;
            }
        }

        println!(
            "errors: {}/{}. accuracy: {}%\n",
            errors,
            inputs.len(),
            100.0 * (1.0 - errors as f32 / inputs.len() as f32)
        );
    }

    /// Run [`Informer`] in binary mode.
    pub fn informer_binary(&self, bitwidths: &[usize], secret_weights: bool) -> eyre::Result<()> {
        let mut informer = Informer::new(Dummy::new());

        Channel::with(std::io::empty(), |channel| {
            let inps = (0..self.ninputs())
                .map(|_| informer.bin_encode(0, bitwidths[0], channel).unwrap())
                .collect::<Vec<_>>();

            self.eval_boolean(
                &mut informer,
                &inps,
                bitwidths,
                secret_weights,
                true,
                channel,
            );
            Ok(())
        })?;
        println!("{}", informer.stats());
        Ok(())
    }

    /// Run [`Informer`] in arithmetic mode.
    pub fn informer_arith(
        &self,
        moduli: &[u128],
        secret_weights: bool,
        accuracy: &Accuracy,
    ) -> eyre::Result<()> {
        let mut informer = Informer::new(Dummy::new());

        Channel::with(std::io::empty(), |channel| {
            let inps = (0..self.ninputs())
                .map(|_| informer.crt_encode(0, moduli[0], channel).unwrap())
                .collect::<Vec<_>>();

            self.eval_arith(
                &mut informer,
                &inps,
                moduli,
                secret_weights,
                true,
                accuracy,
                channel,
            );
            Ok(())
        })?;
        println!("{}", informer.stats());
        Ok(())
    }
}

/// Extract the input shape from a JSON value.
fn input_shape(
    cfg: &serde_json::map::Map<String, Value>,
    layers: &[Layer],
) -> (usize, usize, usize) {
    // input_shape is the target shape for each weights array
    if let Some(v) = cfg.get("batch_input_shape") {
        let mut shape = v.as_array().unwrap().clone();
        if shape[0].is_null() {
            shape.remove(0);
        }
        let height = shape[0].as_u64().unwrap() as usize;
        let width = if shape.len() > 1 {
            shape[1].as_u64().unwrap() as usize
        } else {
            1
        };
        let depth = if shape.len() > 2 {
            shape[2].as_u64().unwrap() as usize
        } else {
            1
        };
        (height, width, depth)
    } else {
        layers.last().expect("no previous layer!").output_dims()
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(non_snake_case)]

    use crate::{Accuracy, NeuralNet, io::read_tests, util};
    use fancy_garbling::WireMod2;
    use ndarray::Array3;
    use std::{ops::Deref, path::Path};
    use swanky_aes_rng::AesRng;

    static DINN_30_DIR: &str = "neural_nets/DINN_30";
    static DINN_30_Bitwidths: [usize; 3] = [9; 3];
    static DINN_100_DIR: &str = "neural_nets/DINN_100";
    static DINN_100_Bitwidths: [usize; 3] = [9; 3];
    static CryptoNets_DIR: &str = "neural_nets/CryptoNets";
    static CryptoNets_Bitwidths: [usize; 11] = [26; 11];
    static DeepSecure_DIR: &str = "neural_nets/DeepSecure";
    static DeepSecure_Bitwidths: [usize; 5] = [24; 5];
    static MiniONN_MNIST: &str = "neural_nets/MiniONN_MNIST";
    static MiniONN_MNIST_Bitwidths: [usize; 8] = [21; 8];

    fn get_nn_and_test(dir: &Path) -> (NeuralNet, Array3<i64>) {
        // Set the base path to `$CARGO_MANIFEST_DIR` for CI.
        let base = env!("CARGO_MANIFEST_DIR");
        let dir = Path::new(base).join(dir);
        let nn = NeuralNet::try_from(dir.deref()).unwrap();
        let tests = read_tests(&dir, Some(1)).unwrap();
        (nn, tests[0].clone())
    }

    fn binary_and_plaintext_match_for_dir(dir: &Path, bitwidths: &[usize]) {
        let (nn, test) = get_nn_and_test(dir);

        let plaintext_output = nn.eval_plaintext(&test);
        let gc_output = nn.eval_roundtrip_binary(&test, bitwidths, false).unwrap();
        for (a, b) in plaintext_output.iter().zip(gc_output.iter()) {
            assert_eq!(a, b);
        }
    }

    fn arithmetic_and_plaintext_match_for_dir(dir: &Path, moduli: &[u128]) {
        let (nn, test) = get_nn_and_test(dir);
        let accuracy = Accuracy {
            relu: "100%".to_string(),
            sign: "100%".to_string(),
            max: "100%".to_string(),
        };

        let plaintext_output = nn.eval_plaintext(&test);
        let gc_output = nn
            .eval_roundtrip_arith(&test, moduli, false, &accuracy)
            .unwrap();
        for (a, b) in plaintext_output.iter().zip(gc_output.iter()) {
            assert_eq!(a, b);
        }
    }

    fn garbling_works_for_model(dir: &str, bitwidths: &[usize]) {
        let (nn, test) = get_nn_and_test(Path::new(dir));
        let (encoder, gc, output_map) = nn
            .gc_garble_boolean::<WireMod2, _>(bitwidths, false, AesRng::new())
            .unwrap();
        // Extract the wirelabels associated with our input of interest.
        let inputs = encoder.encode_inputs(&test, bitwidths[0]);
        // Evaluate the garbled circuit.
        let outputs = nn
            .gc_eval_boolean::<WireMod2>(&inputs, &gc, bitwidths, false)
            .unwrap();
        // Map the output wirelabels to values.
        let output = output_map.to_outputs(&outputs).unwrap();

        let plaintext = nn.eval_plaintext(&test);
        for (a, b) in plaintext.iter().zip(output.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn garbling_works_for_DINN_30() {
        garbling_works_for_model(DINN_30_DIR, &DINN_30_Bitwidths);
    }

    #[test]
    fn garbling_works_for_DINN_100() {
        garbling_works_for_model(DINN_100_DIR, &DINN_100_Bitwidths)
    }

    #[test]
    fn binary_and_plaintext_match_for_DINN_30() {
        binary_and_plaintext_match_for_dir(Path::new(DINN_30_DIR), &DINN_30_Bitwidths);
    }

    #[test]
    fn arithmetic_and_plaintext_match_for_DINN_30() {
        let moduli = util::bitwidths_to_moduli(&DINN_30_Bitwidths);
        arithmetic_and_plaintext_match_for_dir(Path::new(DINN_30_DIR), &moduli);
    }

    #[test]
    fn binary_and_plaintext_match_for_DINN_100() {
        binary_and_plaintext_match_for_dir(Path::new(DINN_100_DIR), &DINN_100_Bitwidths);
    }

    #[test]
    fn arithmetic_and_plaintext_match_for_DINN_100() {
        let moduli = util::bitwidths_to_moduli(&DINN_100_Bitwidths);
        arithmetic_and_plaintext_match_for_dir(Path::new(DINN_100_DIR), &moduli);
    }

    #[test]
    fn binary_and_plaintext_match_for_CryptoNets() {
        binary_and_plaintext_match_for_dir(Path::new(CryptoNets_DIR), &CryptoNets_Bitwidths);
    }

    #[test]
    fn arithmetic_and_plaintext_match_for_CryptoNets() {
        let moduli = util::bitwidths_to_moduli(&CryptoNets_Bitwidths);
        arithmetic_and_plaintext_match_for_dir(Path::new(CryptoNets_DIR), &moduli);
    }

    #[test]
    fn binary_and_plaintext_match_for_DeepSecure() {
        binary_and_plaintext_match_for_dir(Path::new(DeepSecure_DIR), &DeepSecure_Bitwidths);
    }

    #[test]
    fn arithmetic_and_plaintext_match_for_DeepSecure() {
        let moduli = util::bitwidths_to_moduli(&DeepSecure_Bitwidths);
        arithmetic_and_plaintext_match_for_dir(Path::new(DeepSecure_DIR), &moduli);
    }

    // This one almost certainly will take too long.
    // #[test]
    // fn binary_and_plaintext_match_for_MiniONN_CIFAR() {
    //     binary_and_plaintext_match_for_dir(Path::new("neural_nets/MiniONN_CIFAR"), &[...]);
    // }

    #[test]
    fn binary_and_plaintext_match_for_MiniONN_MNIST() {
        binary_and_plaintext_match_for_dir(Path::new(MiniONN_MNIST), &MiniONN_MNIST_Bitwidths);
    }

    // This one fails, need to debug!
    // #[test]
    // fn binary_and_plaintext_match_for_SecureML() {
    //     binary_and_plaintext_match_for_dir(Path::new("neural_nets/SecureML"), &[22; 11]);
    // }
}

//! The lowest level of a [`NeuralNet`](crate::NeuralNet) is a [`Layer`].

use crate::util;
use fancy_garbling::{
    BinaryBundle, BinaryGadgets, CrtBundle, CrtGadgets, Fancy, FancyInput, HasModulus,
};
use fancy_garbling::{FancyArithmetic, util as numbers};
use itertools::iproduct;
use ndarray::Array3;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};

/// The accuracy to use for each activation function.
// TODO: Replace these with an enum. See #361.
#[derive(Clone, Debug)]
pub struct Accuracy {
    /// The accuracy to use for the ReLU activation function.
    pub relu: String,
    /// The accuracy to use for the sign activation function.
    pub sign: String,
    /// The accuracy to use for the max activation function.
    pub max: String,
}

/// The supported activation functions.
pub enum ActivationFunction {
    /// `Sign(x) = { 1 if x ≥ 0, -1 otherwise }`.
    Sign,
    /// `Relu(x) = max(0, x)`.
    Relu,
    /// `Identity(x) = x`.
    Identity,
}

impl std::fmt::Display for ActivationFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivationFunction::Sign => write!(f, "Sign"),
            ActivationFunction::Relu => write!(f, "ReLU"),
            ActivationFunction::Identity => write!(f, "Identity"),
        }
    }
}

/// Map a string to its associated [`ActivationFunction`].
///
/// Not all input activation functions are supported; rather, they are mapped to
/// ones that we do support internally. Below is the mapping from `tensorflow`
/// activation functions:
///
/// - tanh, hard_sigmoid, sign => [`ActivationFunction::Sign`]
/// - relu => [`ActivationFunction::Relu`]
/// - linear, softmax, identity, id => [`ActivationFunction::Identity`]
impl TryFrom<&str> for ActivationFunction {
    type Error = swanky_error::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "tanh" | "hard_sigmoid" | "sign" => Ok(ActivationFunction::Sign),
            "relu" => Ok(ActivationFunction::Relu),
            "linear" | "softmax" | "identity" | "id" => Ok(ActivationFunction::Identity),
            _ => swanky_error::bail!(
                ErrorKind::OtherError,
                "Input is either an invalid or unsupported activation function"
            ),
        }
    }
}

/// A layer of a [`NeuralNet`](crate::NeuralNet).
///
/// Some layers contains optional weights and biases. If they are not present,
/// the weights and biases are treated as secret values (i.e., garbler inputs).
pub enum Layer {
    /// A dense layer.
    Dense {
        /// The layer weights.
        weights: Vec<Array3<Option<i64>>>,
        /// The layer biases.
        biases: Vec<Option<i64>>,
        /// The activation type.
        activation: ActivationFunction,
    },
    /// A convolution layer.
    Convolutional {
        /// The filter weights.
        filters: Vec<Array3<Option<i64>>>,
        /// The layer biases.
        biases: Vec<Option<i64>>,
        /// The input dimensions, given as (height, width, depth).
        input_shape: (usize, usize, usize),
        /// The kernel dimensions, given as (height, width, depth).
        kernel_shape: (usize, usize, usize),
        /// The stride, given as (y, x).
        stride: (usize, usize),
        /// The activation type.
        activation: ActivationFunction,
        /// Whether to apply padding or not.
        pad: bool,
    },
    /// A max pooling layer.
    MaxPooling2D {
        /// The input dimensions, given as (height, width, depth).
        input_shape: (usize, usize, usize),
        /// The stride, given as (y, x).
        stride: (usize, usize),
        /// The size, given as (height, width).
        size: (usize, usize),
        /// Whether to apply padding or not.
        pad: bool,
    },
    /// A flatten layer.
    Flatten {
        /// The input dimensions, given as (height, width, depth).
        input_shape: (usize, usize, usize),
        /// The output dimensions, given as (height, width, depth).
        output_shape: (usize, usize, usize),
    },
    /// An activation layer.
    Activation {
        /// The activation type.
        activation: ActivationFunction,
        /// The input dimensions, given as (height, width, depth).
        input_shape: (usize, usize, usize),
    },
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer::Dense { .. } => write!(f, "Dense"),
            Layer::Convolutional { .. } => write!(f, "Convolutional"),
            Layer::MaxPooling2D { .. } => write!(f, "MaxPooling2D"),
            Layer::Flatten { .. } => write!(f, "Flatten"),
            Layer::Activation { .. } => write!(f, "Activation"),
        }
    }
}

impl std::fmt::Debug for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer::Dense { activation, .. } => {
                let (height, _, _) = self.output_dims();
                write!(f, "Dense[{height}] activation={activation}")
            }
            Layer::Convolutional {
                kernel_shape,
                stride,
                filters,
                activation,
                ..
            } => write!(
                f,
                "Conv[{}] activation={activation} stride={stride:?} kernel_shape={kernel_shape:?}",
                filters.len(),
            ),
            Layer::MaxPooling2D { stride, size, .. } => {
                write!(f, "MaxPooling2D stride={stride:?} size={size:?}")
            }
            Layer::Flatten { .. } => write!(f, "Flatten"),
            Layer::Activation { activation, .. } => write!(f, "Activation {activation}"),
        }
    }
}

/// Encodes the particular way that we evaluate a neural net - whether it is
/// directly over `i64` or as an arithmetic circuit, or whatever. The first
/// argument to these functions could be a [`Fancy`] object.
struct NeuralNetOps<
    F,
    T,
    ENCODE: Fn(&mut F, i64, &mut Channel) -> Result<T>,
    SECRET: Fn(&mut F, Option<i64>, &mut Channel) -> Result<T>,
    ADD: Fn(&mut F, &T, &T, &mut Channel) -> Result<T>,
    CMUL: Fn(&mut F, &T, i64, &mut Channel) -> Result<T>,
    PROJ: Fn(&mut F, &T, Option<i64>, &mut Channel) -> Result<T>,
    MAX: Fn(&mut F, &[T], &mut Channel) -> Result<T>,
    ACTIVATION: Fn(&mut F, &ActivationFunction, &T, &mut Channel) -> Result<T>,
    ZERO: Fn(&mut F, &mut Channel) -> Result<T>,
> {
    // Encode a constant.
    enc: ENCODE,
    // Encode a secret.
    sec: SECRET,
    // Add two values.
    add: ADD,
    // Scalar multiplication.
    cmul: CMUL,
    // Apply secret weight to an input.
    proj: PROJ,
    // Maximum of a slice of encodings.
    max: MAX,
    // Activation function.
    act: ACTIVATION,
    // Encode a zero value.
    zero: ZERO,
    f: PhantomData<F>,
}

impl Layer {
    /// The input dimensions as a tuple of (height, width, depth).
    pub fn input_dims(&self) -> (usize, usize, usize) {
        match self {
            Layer::Dense { weights, .. } => weights.iter().next().map_or((0, 0, 0), |w0| w0.dim()),
            Layer::Convolutional { input_shape, .. }
            | Layer::MaxPooling2D { input_shape, .. }
            | Layer::Flatten { input_shape, .. }
            | Layer::Activation { input_shape, .. } => *input_shape,
        }
    }

    /// The number of items in the input.
    pub fn input_size(&self) -> usize {
        let (x, y, z) = self.input_dims();
        x * y * z
    }

    /// The output dimensions as a tuple of (height, width, depth).
    pub fn output_dims(&self) -> (usize, usize, usize) {
        match self {
            Layer::Dense { biases, .. } => (biases.len(), 1, 1),
            Layer::Convolutional {
                input_shape,
                kernel_shape,
                stride,
                filters,
                pad,
                ..
            } => {
                let (height, width, _) = input_shape;
                let (ker_height, ker_width, _) = kernel_shape;
                let (stride_y, stride_x) = stride;

                if *pad {
                    (*height, *width, filters.len())
                } else {
                    (
                        (height - ker_height) / stride_y + 1,
                        (width - ker_width) / stride_x + 1,
                        filters.len(),
                    )
                }
            }
            Layer::MaxPooling2D {
                input_shape,
                stride,
                size,
                pad,
            } => {
                let (height, width, depth) = input_shape;
                let (pool_height, pool_width) = size;
                let (stride_y, stride_x) = stride;

                if *pad {
                    *input_shape
                } else {
                    (
                        (height - pool_height) / stride_y + 1,
                        (width - pool_width) / stride_x + 1,
                        *depth,
                    )
                }
            }
            Layer::Flatten { output_shape, .. } => *output_shape,
            Layer::Activation { input_shape, .. } => *input_shape,
        }
    }

    /// The number of items in the output.
    pub fn output_size(&self) -> usize {
        let (x, y, z) = self.output_dims();
        x * y * z
    }

    /// Evaluate this layer in plaintext, returning the layer output alongside
    /// the max value on a wire.
    pub fn max_bitwidth(
        &self,
        input: &Array3<i64>,
        channel: &mut Channel,
    ) -> Result<(Array3<i64>, i64)> {
        let max_atomic = AtomicUsize::new(0);
        let store_max_base = Arc::new(move |x: i64| -> usize {
            max_atomic.fetch_max(x.unsigned_abs() as usize, Ordering::SeqCst)
        });

        let store_max = store_max_base.clone();
        let enc = move |_: &mut usize, x: i64, _: &mut Channel| {
            store_max(x);
            Ok(x)
        };

        let store_max = store_max_base.clone();
        let proj = move |_: &mut usize, inp: &i64, opt_w, _: &mut Channel| {
            if let Some(w) = opt_w {
                let x = w * inp;
                store_max(x);
                Ok(x)
            } else {
                Ok(*inp)
            }
        };

        let store_max = store_max_base.clone();
        let add = move |_: &mut usize, x: &i64, y: &i64, _: &mut Channel| {
            let res = x + y;
            store_max(res);
            Ok(res)
        };

        let store_max = store_max_base.clone();
        let cmul = move |_: &mut usize, x: &i64, y: i64, _: &mut Channel| {
            let res = x * y;
            store_max(res);
            Ok(res)
        };

        let store_max = store_max_base.clone();
        let max = move |_: &mut usize, xs: &[i64], _: &mut Channel| {
            Ok(xs
                .iter()
                .map(|&x| {
                    store_max(x);
                    x
                })
                .max()
                .unwrap_or(0))
        };

        let act = |_: &mut usize, a: &ActivationFunction, x: &i64, _: &mut Channel| match a {
            ActivationFunction::Sign => {
                if *x >= 0 {
                    Ok(1)
                } else {
                    Ok(-1)
                }
            }
            ActivationFunction::Relu => Ok(std::cmp::max(*x, 0)),
            ActivationFunction::Identity => Ok(*x),
        };

        let ops = NeuralNetOps {
            enc,
            sec: |_, _, _| Ok(0),
            add,
            cmul,
            proj,
            max,
            act,
            zero: |_, _| Ok(0),
            f: PhantomData,
        };

        let layer_output = self.eval(&mut 0, input, ops, false, channel)?;
        let max_val = store_max_base(0) as i64;
        Ok((layer_output, max_val))
    }

    /// Evaluate the layer in plaintext.
    pub fn as_plaintext(&self, input: &Array3<i64>, channel: &mut Channel) -> Result<Array3<i64>> {
        let ops = NeuralNetOps {
            enc: |_, x, _| Ok(x),
            sec: |_, _, _| {
                unreachable!("There are no secret weights, so this should be unreachable!")
            },
            add: |_, x, y, _| Ok(x + y),
            cmul: |_, x, y, _| Ok(x * y),
            proj: |_, _, _, _| {
                unreachable!(
                    "Projection gates are only used for secret weights, which shouldn't exist in plaintext evaluation!"
                )
            },
            max: |_, xs, _| Ok(*xs.iter().max().unwrap_or(&0)),
            act: |_, a, x, _| match a {
                ActivationFunction::Sign => {
                    if *x >= 0 {
                        Ok(1)
                    } else {
                        Ok(-1)
                    }
                }
                ActivationFunction::Relu => Ok(std::cmp::max(*x, 0)),
                ActivationFunction::Identity => Ok(*x),
            },
            zero: |_, _| Ok(0),
            f: PhantomData,
        };

        self.eval(&mut 0, input, ops, false, channel)
    }

    /// Evaluate the layer using arithmetic garbled circuits.
    ///
    /// # Panics
    /// Panics if `self.input_dims()` does not equal `input.dims()`.
    #[allow(clippy::too_many_arguments)]
    pub fn as_arith<F, W>(
        &self,
        f: &mut F,
        input_modulus: u128,
        output_modulus: u128,
        input: &Array3<CrtBundle<W>>,
        secret_weights: bool,
        secret_weights_owned: bool,
        accuracy: &Accuracy,
        channel: &mut Channel,
    ) -> Result<Array3<CrtBundle<W>>>
    where
        W: Clone + HasModulus,
        F: Fancy<Item = W>
            + FancyInput<Item = W>
            + FancyArithmetic<Item = W>
            + CrtGadgets<Item = W>,
    {
        let relu_accuracy = accuracy.relu.clone();
        let sign_accuracy = accuracy.sign.clone();
        let max_accuracy = accuracy.max.clone();

        let q = input_modulus;
        let output_ps = numbers::factor(output_modulus);

        let ops = NeuralNetOps {
            enc: |b: &mut F, x, channel| b.crt_constant_bundle(util::to_mod_q(x, q), q, channel),

            sec: |b: &mut F, opt_x, channel| {
                if secret_weights_owned {
                    b.crt_encode(util::to_mod_q(opt_x.unwrap(), q), q, channel)
                } else {
                    b.crt_receive(q, channel)
                }
            },

            add: |b: &mut F, x, y, _| Ok(b.crt_add(x, y)),

            cmul: |b: &mut F, x, y, _| Ok(b.crt_cmul(x, util::to_mod_q(y, q))),

            proj: |b: &mut F, inp, opt_w, channel| {
                if let Some(w) = opt_w {
                    // convert the weight to crt mod q
                    let ws = util::to_mod_q_crt(w, q);
                    Ok(CrtBundle::new(
                        inp.wires()
                            .iter()
                            .zip(ws.iter())
                            .map(|(wire, weight)| {
                                let q = wire.modulus();
                                let tab = (0..q).map(|x| x * weight % q).collect::<Vec<_>>();
                                // project each input x to x*w
                                b.proj(wire, q, Some(tab), channel)
                            })
                            .collect::<Result<Vec<_>>>()?,
                    ))
                } else {
                    Ok(CrtBundle::new(
                        inp.wires()
                            .iter()
                            .map(|wire| {
                                // project the input, without knowing the weight
                                b.proj(wire, wire.modulus(), None, channel)
                            })
                            .collect::<Result<Vec<_>>>()?,
                    ))
                }
            },
            max: |b: &mut F, xs: &[CrtBundle<W>], channel| b.crt_max(xs, &max_accuracy, channel),
            act: |b: &mut F, a, x: &CrtBundle<W>, channel| match a {
                ActivationFunction::Sign => b.crt_sgn(x, &sign_accuracy, Some(&output_ps), channel),
                ActivationFunction::Relu => {
                    b.crt_relu(x, &relu_accuracy, Some(&output_ps), channel)
                }
                ActivationFunction::Identity => Ok(x.clone()),
            },
            zero: |b: &mut F, channel: &mut Channel| b.crt_constant_bundle(0, q, channel),
            f: PhantomData,
        };

        self.eval(f, input, ops, secret_weights, channel)
    }

    /// Evaluate the layer using binary garbled circuits.
    ///
    /// # Panics
    /// Panics if `self.input_dims()` does not equal `input.dims()`.
    pub fn as_binary<F, W>(
        &self,
        f: &mut F,
        nbits: usize,
        input: &Array3<BinaryBundle<W>>,
        secret_weights: bool,
        secret_weights_owned: bool,
        channel: &mut Channel,
    ) -> Result<Array3<BinaryBundle<W>>>
    where
        W: Clone + HasModulus,
        F: Fancy<Item = W> + FancyInput<Item = W> + BinaryGadgets<Item = W>,
    {
        let ops = NeuralNetOps {
            enc: |b: &mut F, x, channel| {
                let twos = util::i64_to_twos_complement(x, nbits);
                b.bin_constant_bundle(twos, nbits, channel)
            },

            sec: |b: &mut F, opt_x, channel| {
                if secret_weights_owned {
                    let xbits = util::i64_to_twos_complement(opt_x.unwrap(), nbits);
                    b.bin_encode(xbits, nbits, channel)
                } else {
                    b.bin_receive(nbits, channel)
                }
            },

            add: |b: &mut F, x, y, channel| b.bin_addition_no_carry(x, y, channel),

            cmul: |b: &mut F, x, y, channel| {
                b.bin_cmul(x, util::i64_to_twos_complement(y, nbits), nbits, channel)
            },

            proj: |b: &mut F, inp, opt_w, channel| {
                // ignore the input weight - it needs to be a garbler input
                let weight_bits = opt_w.map(|w| util::i64_to_twos_complement(w, nbits));
                let w = if secret_weights_owned {
                    b.bin_encode(weight_bits.unwrap(), nbits, channel)?
                } else {
                    b.bin_receive(nbits, channel)?
                };
                b.bin_multiplication_lower_half(inp, &w, channel)
            },

            max: |b: &mut F, xs, channel| b.bin_max(xs, channel),

            act: |b: &mut F, a, x: &BinaryBundle<W>, channel: &mut Channel| match a {
                ActivationFunction::Sign => {
                    let sign = x.wires().last().unwrap();
                    let neg1 = (1 << nbits) - 1;
                    b.bin_multiplex_constant_bits(sign, 1, neg1, nbits, channel)
                }
                ActivationFunction::Relu => {
                    let sign = x.wires().last().unwrap();
                    let zeros = b.bin_constant_bundle(0u128, nbits, channel)?;
                    b.bin_multiplex(sign, x, &zeros, channel)
                }
                ActivationFunction::Identity => Ok(x.clone()),
            },

            zero: |b: &mut F, channel: &mut Channel| b.bin_constant_bundle(0u128, nbits, channel),
            f: PhantomData,
        };
        self.eval(f, input, ops, secret_weights, channel)
    }

    /// Evaluate the layer over the specified [`NeuralNetOps`].
    ///
    /// # Panics
    /// Panics if `self.input_dims()` does not equal `input.dims()`.
    fn eval<
        F,
        T,
        ENCODE: Fn(&mut F, i64, &mut Channel) -> Result<T>,
        SECRET: Fn(&mut F, Option<i64>, &mut Channel) -> Result<T>,
        ADD: Fn(&mut F, &T, &T, &mut Channel) -> Result<T>,
        CMUL: Fn(&mut F, &T, i64, &mut Channel) -> Result<T>,
        PROJ: Fn(&mut F, &T, Option<i64>, &mut Channel) -> Result<T>,
        MAX: Fn(&mut F, &[T], &mut Channel) -> Result<T>,
        ACTIVATION: Fn(&mut F, &ActivationFunction, &T, &mut Channel) -> Result<T>,
        ZERO: Fn(&mut F, &mut Channel) -> Result<T>,
    >(
        &self,
        b: &mut F,
        input: &Array3<T>,
        ops: NeuralNetOps<F, T, ENCODE, SECRET, ADD, CMUL, PROJ, MAX, ACTIVATION, ZERO>,
        secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<Array3<T>>
    where
        T: Clone,
    {
        assert_eq!(self.input_dims(), input.dim());
        let (height, width, depth) = self.input_dims();

        let mut output: Array3<Option<T>> = Array3::default(self.output_dims());
        let nouts = self.output_size();

        match self {
            Layer::Dense {
                weights,
                biases,
                activation,
            } => {
                for neuron in 0..nouts {
                    let mut x = if secret_weights {
                        (ops.sec)(b, biases[neuron], channel)?
                    } else {
                        (ops.enc)(
                            b,
                            biases[neuron].expect("biases required for evaluation"),
                            channel,
                        )?
                    };

                    for i in 0..height {
                        for j in 0..width {
                            for k in 0..depth {
                                let prod = if secret_weights {
                                    (ops.proj)(
                                        b,
                                        &input[(i, j, k)],
                                        weights[neuron][(i, j, k)],
                                        channel,
                                    )?
                                } else {
                                    let w = weights[neuron][(i, j, k)]
                                        .expect("weights required for evaluation");
                                    (ops.cmul)(b, &input[(i, j, k)], w, channel)?
                                };
                                x = (ops.add)(b, &x, &prod, channel)?;
                            }
                        }
                    }

                    let z = (ops.act)(b, activation, &x, channel)?;
                    output[(neuron, 0, 0)] = Some(z);
                }
            }

            Layer::Convolutional {
                filters,
                biases,
                kernel_shape,
                stride,
                activation,
                pad,
                ..
            } => {
                let (kheight, kwidth, kdepth) = *kernel_shape;
                let (stride_y, stride_x) = *stride;

                let zero_rows = if *pad {
                    (stride_y - 1) * height + kheight - stride_y
                } else {
                    0
                };
                let zero_cols = if *pad {
                    (stride_x - 1) * width + kwidth - stride_x
                } else {
                    0
                };

                let shift_y = ((zero_rows as f32) / 2.0).floor() as usize;
                let shift_x = ((zero_cols as f32) / 2.0).floor() as usize;

                for filterno in 0..filters.len() {
                    let mut h = 0;
                    while stride_y * h <= height - kheight + zero_rows {
                        let mut w = 0;
                        while stride_x * w <= width - kwidth + zero_cols {
                            let mut x = if secret_weights {
                                (ops.sec)(b, biases[filterno], channel)?
                            } else {
                                (ops.enc)(
                                    b,
                                    biases[filterno].expect("biases required for evaluation"),
                                    channel,
                                )?
                            };

                            for i in 0..kheight {
                                let idx_y = stride_y * h + i;
                                for j in 0..kwidth {
                                    let idx_x = stride_x * w + j;
                                    for k in 0..kdepth {
                                        let pad_condition = *pad
                                            && ((idx_y < shift_y || idx_x < shift_x)
                                                || (idx_y >= height + shift_y
                                                    || idx_x >= width + shift_x));

                                        let input_val = if pad_condition {
                                            &(ops.zero)(b, channel)?
                                        } else {
                                            &input[(idx_y - shift_y, idx_x - shift_x, k)]
                                        };

                                        let prod = if secret_weights {
                                            (ops.proj)(
                                                b,
                                                input_val,
                                                filters[filterno][(i, j, k)],
                                                channel,
                                            )?
                                        } else {
                                            (ops.cmul)(
                                                b,
                                                input_val,
                                                filters[filterno][(i, j, k)]
                                                    .expect("weights required for evaluation"),
                                                channel,
                                            )?
                                        };
                                        x = (ops.add)(b, &x, &prod, channel)?;
                                    }
                                }
                            }

                            let z = (ops.act)(b, activation, &x, channel)?;
                            assert!(output[(h, w, filterno)].is_none());
                            output[(h, w, filterno)] = Some(z);
                            w += 1;
                        }
                        h += 1;
                    }
                }
            }

            Layer::MaxPooling2D {
                stride, size, pad, ..
            } => {
                let (pheight, pwidth) = *size;
                let (stride_y, stride_x) = *stride;

                let zero_rows = if *pad {
                    (stride_y - 1) * height + pheight - stride_y
                } else {
                    0
                };
                let zero_cols = if *pad {
                    (stride_x - 1) * width + pwidth - stride_x
                } else {
                    0
                };

                let shift_y = ((zero_rows as f32) / 2.0).floor() as usize;
                let shift_x = ((zero_cols as f32) / 2.0).floor() as usize;

                // create windows
                let mut windows = Vec::new();
                let mut y = 0;
                while stride_y * y <= height - pheight + zero_rows {
                    let mut x = 0;
                    while stride_x * x <= width - pwidth + zero_cols {
                        for z in 0..depth {
                            let mut vals = Vec::with_capacity(pheight * pwidth);
                            for h in 0..pheight {
                                let idx_y = stride_y * y + h;
                                for w in 0..pwidth {
                                    let idx_x = stride_x * x + w;

                                    let pad_condition = *pad
                                        && ((idx_y < shift_y || idx_x < shift_x)
                                            || (idx_y >= height + shift_y
                                                || idx_x >= width + shift_x));

                                    let val = if pad_condition {
                                        (ops.zero)(b, channel)?.clone()
                                    } else {
                                        input[(idx_y - shift_y, idx_x - shift_x, z)].clone()
                                    };

                                    vals.push(val);
                                }
                            }
                            windows.push(((y, x, z), vals));
                        }
                        x += 1;
                    }
                    y += 1;
                }

                for (coordinate, window) in windows.into_iter() {
                    let val = (ops.max)(b, &window, channel)?;
                    output[coordinate] = Some(val);
                }
            }

            Layer::Flatten { output_shape, .. } => {
                output = input.map(|v| Option::Some(v.clone()));
                output = output
                    .into_shape(*output_shape)
                    .expect("output shape is invalid");
            }

            Layer::Activation { activation, .. } => {
                let coordinates = iproduct!(0..height, 0..width, 0..depth).collect::<Vec<_>>();
                for c in coordinates.into_iter() {
                    let z = (ops.act)(b, activation, &input[c], channel)?;
                    output[c] = Some(z);
                }
            }
        }

        for (coordinate, val) in output.indexed_iter() {
            swanky_error::ensure!(
                val.is_some(),
                ErrorKind::OtherError,
                "{self}: uninitialized output at {coordinate:?}"
            );
        }

        Ok(output.mapv(
            |elem| elem.unwrap(), // Ok `unwrap`: we checked above that all the outputs are not `None`.
        ))
    }
}

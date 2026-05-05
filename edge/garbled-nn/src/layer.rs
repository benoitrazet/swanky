//! The lowest level of a [`NeuralNet`](crate::NeuralNet) is a [`Layer`].

use crate::layer::activation::LayerActivation;
use crate::layer::convolutional::LayerConvolutional;
use crate::layer::dense::LayerDense;
use crate::layer::flatten::LayerFlatten;
use crate::layer::max_pooling_2d::LayerMaxPooling2D;
use crate::neural_net::{FancyNeuralNet, NeuralNetExecutor};
use ndarray::Array3;
use std::fmt::Debug;
use std::fmt::Display;
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

/// An enum of the supported neural network layers.
pub(crate) enum Layers {
    Dense(LayerDense),
    Convolutional(LayerConvolutional),
    MaxPooling2D(LayerMaxPooling2D),
    Flatten(LayerFlatten),
    Activation(LayerActivation),
}

impl Layers {
    /// Evaluate the layer on the provided backend.
    ///
    /// The `secret_weights` argument denotes whether the neural net weights are
    /// secret to the garbler or not.
    pub(crate) fn eval<F: FancyNeuralNet>(
        &self,
        backend: &mut F,
        input: Array3<F::Item>,
        secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<Array3<F::Item>> {
        match self {
            Layers::Dense(layer) => layer.execute(backend, input, secret_weights, channel),
            Layers::Convolutional(layer) => layer.execute(backend, input, secret_weights, channel),
            Layers::MaxPooling2D(layer) => layer.execute(backend, input, secret_weights, channel),
            Layers::Flatten(layer) => layer.execute(backend, input, secret_weights, channel),
            Layers::Activation(layer) => layer.execute(backend, input, secret_weights, channel),
        }
    }
}

impl Layer for Layers {
    fn input_dims(&self) -> (usize, usize, usize) {
        match self {
            Layers::Dense(layer) => layer.input_dims(),
            Layers::Convolutional(layer) => layer.input_dims(),
            Layers::MaxPooling2D(layer) => layer.input_dims(),
            Layers::Flatten(layer) => layer.input_dims(),
            Layers::Activation(layer) => layer.input_dims(),
        }
    }

    fn output_dims(&self) -> (usize, usize, usize) {
        match self {
            Layers::Dense(layer) => layer.output_dims(),
            Layers::Convolutional(layer) => layer.output_dims(),
            Layers::MaxPooling2D(layer) => layer.output_dims(),
            Layers::Flatten(layer) => layer.output_dims(),
            Layers::Activation(layer) => layer.output_dims(),
        }
    }
}

impl core::fmt::Display for Layers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layers::Dense(layer) => write!(f, "{layer}"),
            Layers::Convolutional(layer) => write!(f, "{layer}"),
            Layers::MaxPooling2D(layer) => write!(f, "{layer}"),
            Layers::Flatten(layer) => write!(f, "{layer}"),
            Layers::Activation(layer) => write!(f, "{layer}"),
        }
    }
}

impl core::fmt::Debug for Layers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dense(layer) => f.debug_tuple("Dense").field(layer).finish(),
            Self::Convolutional(layer) => f.debug_tuple("Convolutional").field(layer).finish(),
            Self::MaxPooling2D(layer) => f.debug_tuple("MaxPooling2D").field(layer).finish(),
            Self::Flatten(layer) => f.debug_tuple("Flatten").field(layer).finish(),
            Self::Activation(layer) => f.debug_tuple("Activation").field(layer).finish(),
        }
    }
}

pub(crate) mod activation;
pub(crate) mod convolutional;
pub(crate) mod dense;
pub(crate) mod flatten;
pub(crate) mod max_pooling_2d;

/// A layer of a [`NeuralNet`](crate::NeuralNet).
///
/// Some layers contains optional weights and biases. If they are not present,
/// the weights and biases are treated as secret values (i.e., garbler inputs).
pub(crate) trait Layer: Display + Debug {
    /// The input dimensions as a tuple of (height, width, depth).
    fn input_dims(&self) -> (usize, usize, usize);

    /// The output dimensions as a tuple of (height, width, depth).
    fn output_dims(&self) -> (usize, usize, usize);

    /// The number of items in the input.
    fn input_size(&self) -> usize {
        let (x, y, z) = self.input_dims();
        x * y * z
    }
}

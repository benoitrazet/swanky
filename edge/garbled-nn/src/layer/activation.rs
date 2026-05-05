use itertools::iproduct;
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::Result;

use crate::{
    ActivationFunction,
    layer::Layer,
    neural_net::{FancyNeuralNet, NeuralNetExecutor},
};

pub(crate) struct LayerActivation {
    /// The activation type.
    pub(crate) activation: ActivationFunction,
    /// The dimensions, given as (height, width, depth).
    pub(crate) shape: (usize, usize, usize),
}

impl core::fmt::Display for LayerActivation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Activation")
    }
}

impl core::fmt::Debug for LayerActivation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Activation {}", self.activation)
    }
}

impl Layer for LayerActivation {
    fn input_dims(&self) -> (usize, usize, usize) {
        self.shape
    }

    fn output_dims(&self) -> (usize, usize, usize) {
        self.shape
    }
}

impl<F: FancyNeuralNet> NeuralNetExecutor<F> for LayerActivation {
    fn execute(
        &self,
        backend: &mut F,
        inputs: Array3<F::Item>,
        _secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<Array3<F::Item>> {
        let mut output = Array3::default(self.output_dims());

        let (height, width, depth) = self.input_dims();
        let coordinates = iproduct!(0..height, 0..width, 0..depth).collect::<Vec<_>>();
        for c in coordinates.into_iter() {
            let z = backend.nn_activation(&self.activation, &inputs[c], channel)?;
            output[c] = Some(z);
        }
        Ok(output.mapv(|elem| elem.unwrap()))
    }
}

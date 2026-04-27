use crate::{
    layer::Layer,
    neural_net::{FancyNeuralNet, NeuralNetExecutor},
};
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};

pub(crate) struct LayerFlatten {
    /// The input dimensions, given as (height, width, depth).
    pub(crate) input_shape: (usize, usize, usize),
    /// The output dimensions, given as (height, width, depth).
    pub(crate) output_shape: (usize, usize, usize),
}

impl core::fmt::Display for LayerFlatten {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Flatten")
    }
}

impl core::fmt::Debug for LayerFlatten {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Flatten")
    }
}

impl Layer for LayerFlatten {
    fn input_dims(&self) -> (usize, usize, usize) {
        self.input_shape
    }

    fn output_dims(&self) -> (usize, usize, usize) {
        self.output_shape
    }
}

impl<F: FancyNeuralNet> NeuralNetExecutor<F> for LayerFlatten {
    fn execute(
        &self,
        _: &mut F,
        inputs: &Array3<F::Item>,
        _: bool,
        _: &mut Channel,
    ) -> Result<Array3<F::Item>> {
        let output = inputs.map(|v| Option::Some(v.clone()));
        let output = output
            .into_shape(self.output_shape)
            .wrap_err(ErrorKind::OtherError, "Invalid output shape")?;
        Ok(output.mapv(|elem| elem.unwrap()))
    }
}

use crate::{
    ActivationFunction,
    layer::Layer,
    neural_net::{FancyNeuralNet, NeuralNetExecutor},
};
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::Result;

pub(crate) struct LayerDense {
    /// The layer weights.
    pub(crate) weights: Vec<Array3<Option<i64>>>,
    /// The layer biases.
    pub(crate) biases: Vec<Option<i64>>,
    /// The activation type.
    pub(crate) activation: ActivationFunction,
}

impl core::fmt::Display for LayerDense {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Dense")
    }
}

impl core::fmt::Debug for LayerDense {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (height, _, _) = self.output_dims();
        write!(f, "Dense[{height}] activation={}", self.activation)
    }
}

impl Layer for LayerDense {
    fn input_dims(&self) -> (usize, usize, usize) {
        self.weights.first().map_or((0, 0, 0), |w0| w0.dim())
    }

    fn output_dims(&self) -> (usize, usize, usize) {
        (self.biases.len(), 1, 1)
    }
}

impl<F: FancyNeuralNet> NeuralNetExecutor<F> for LayerDense {
    fn execute(
        &self,
        backend: &mut F,
        inputs: &Array3<F::Item>,
        secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<Array3<F::Item>> {
        let mut output = Array3::default(self.output_dims());

        let (height, width, depth) = self.input_dims();
        let output_dims = self.output_dims();
        let nouts = output_dims.0 * output_dims.1 * output_dims.2;

        for neuron in 0..nouts {
            let mut x = if secret_weights {
                backend.nn_secret(self.biases[neuron], channel)?
            } else {
                backend.nn_encode(
                    self.biases[neuron].expect("biases required for evaluation"),
                    channel,
                )?
            };

            for i in 0..height {
                for j in 0..width {
                    for k in 0..depth {
                        let prod = if secret_weights {
                            backend.nn_proj(
                                &inputs[(i, j, k)],
                                self.weights[neuron][(i, j, k)],
                                channel,
                            )?
                        } else {
                            let w = self.weights[neuron][(i, j, k)]
                                .expect("weights required for evaluation");
                            backend.nn_cmul(&inputs[(i, j, k)], w, channel)?
                        };
                        x = backend.nn_add(&x, &prod, channel)?;
                    }
                }
            }

            let z = backend.nn_activation(&self.activation, &x, channel)?;
            output[(neuron, 0, 0)] = Some(z);
        }
        Ok(output.mapv(|elem| elem.unwrap()))
    }
}

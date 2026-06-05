use crate::{ActivationFunction, NeuralNet, neural_net::FancyNeuralNet};
use core::cmp::max;
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::Result;

/// Evaluate a [`NeuralNet`] over a plaintext input, outputting a vector
/// containing the maximum bitwidths required for each layer of the neural
/// network.
pub(crate) fn eval(nn: &NeuralNet, inputs: &Array3<i64>) -> Result<Vec<usize>> {
    let mut max_nbits: Vec<usize> = vec![0; nn.layers.len()];

    Channel::with(std::io::empty(), |channel| {
        let mut acc = inputs.clone();
        for (i, layer) in nn.layers.iter().enumerate() {
            let mut backend = BitwidthLayer { max: 0 };
            acc = layer.eval(&mut backend, acc, false, channel)?;
            let new_max_val = backend.max;

            let nbits = if new_max_val < 0 {
                (1.0 + ((-new_max_val) as f64).log2().ceil()) as usize
            } else {
                (new_max_val as f64).log2().ceil() as usize
            };

            if nbits > max_nbits[i] {
                max_nbits[i] = nbits;
            }
        }
        Ok(())
    })?;
    Ok(max_nbits)
}

struct BitwidthLayer {
    max: i64,
}

impl FancyNeuralNet for BitwidthLayer {
    type Item = i64;

    fn nn_encode(&mut self, value: i64, _: &mut Channel) -> Result<Self::Item> {
        self.max = max(self.max, value);
        Ok(value)
    }

    fn nn_secret(&mut self, _: Option<i64>, _: &mut Channel) -> Result<Self::Item> {
        Ok(0)
    }

    fn nn_add(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        let z = x + y;
        self.max = max(self.max, z);
        Ok(z)
    }

    fn nn_cmul(&mut self, x: &Self::Item, constant: i64, _: &mut Channel) -> Result<Self::Item> {
        let z = x * constant;
        self.max = max(self.max, z);
        Ok(z)
    }

    fn nn_proj(&mut self, x: &Self::Item, tt: Option<i64>, _: &mut Channel) -> Result<Self::Item> {
        if let Some(w) = tt {
            let z = w * x;
            self.max = max(self.max, z);
            Ok(z)
        } else {
            Ok(*x)
        }
    }

    fn nn_max(&mut self, xs: &[Self::Item], _: &mut Channel) -> Result<Self::Item> {
        Ok(xs
            .iter()
            .map(|&x| {
                self.max = max(self.max, x);
                x
            })
            .max()
            .unwrap_or(0))
    }

    fn nn_activation(
        &mut self,
        f: &ActivationFunction,
        x: &Self::Item,
        _: &mut Channel,
    ) -> Result<Self::Item> {
        match f {
            ActivationFunction::Sign => {
                if *x >= 0 {
                    Ok(1)
                } else {
                    Ok(-1)
                }
            }
            ActivationFunction::Relu => Ok(max(*x, 0)),
            ActivationFunction::Identity => Ok(*x),
        }
    }

    fn nn_zero(&mut self, _: &mut Channel) -> Result<Self::Item> {
        Ok(0)
    }
}

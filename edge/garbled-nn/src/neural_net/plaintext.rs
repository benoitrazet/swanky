use crate::{ActivationFunction, NeuralNet, neural_net::FancyNeuralNet};
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::Result;

/// Object for evaluating a [`NeuralNet`] over plaintext values.
pub(crate) struct PlaintextNeuralNet;

impl PlaintextNeuralNet {
    /// Evaluate a [`NeuralNet`] over plaintext values.
    pub fn eval(nn: &NeuralNet, input: &Array3<i64>) -> Result<Array3<i64>> {
        let mut backend = PlaintextNeuralNet;
        Channel::with(std::io::empty(), |channel| {
            nn.layers.iter().try_fold(input.clone(), |acc, layer| {
                layer.eval(&mut backend, acc, false, channel)
            })
        })
    }
}

impl FancyNeuralNet for PlaintextNeuralNet {
    type Item = i64;

    fn nn_encode(&mut self, value: i64, _: &mut Channel) -> Result<i64> {
        Ok(value)
    }

    fn nn_secret(&mut self, _value: Option<i64>, _: &mut Channel) -> Result<i64> {
        unreachable!("There are no secret weights, so this should be unreachable!")
    }

    fn nn_add(&mut self, x: &i64, y: &i64, _: &mut Channel) -> Result<i64> {
        Ok(x + y)
    }

    fn nn_cmul(&mut self, x: &i64, constant: i64, _: &mut Channel) -> Result<i64> {
        Ok(x * constant)
    }

    fn nn_proj(&mut self, _x: &i64, _tt: Option<i64>, _: &mut Channel) -> Result<i64> {
        unreachable!(
            "Projection gates are only used for secret weights, which shouldn't exist in plaintext evaluation!"
        )
    }

    fn nn_max(&mut self, xs: &[i64], _: &mut Channel) -> Result<i64> {
        Ok(*xs.iter().max().unwrap_or(&0))
    }

    fn nn_activation(
        &mut self,
        f: &crate::ActivationFunction,
        x: &i64,
        _: &mut Channel,
    ) -> Result<i64> {
        match f {
            ActivationFunction::Sign => {
                if *x >= 0 {
                    Ok(1)
                } else {
                    Ok(-1)
                }
            }
            ActivationFunction::Relu => Ok(std::cmp::max(*x, 0)),
            ActivationFunction::Identity => Ok(*x),
        }
    }

    fn nn_zero(&mut self, _: &mut Channel) -> Result<i64> {
        Ok(0)
    }
}

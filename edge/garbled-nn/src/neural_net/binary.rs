use crate::{
    ActivationFunction, NeuralNet,
    layer::Layer,
    neural_net::FancyNeuralNet,
    util::{i64_from_bits, i64_to_twos_complement},
};
use fancy_garbling::{BinaryBundle, BinaryGadgets, Fancy};
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};

pub struct BinaryNeuralNet<'a, F> {
    backend: &'a mut F,
    bitwidths: &'a [usize],
    secret_weights_owned: bool,
}

impl<'a, F: BinaryGadgets> BinaryNeuralNet<'a, F> {
    pub(crate) fn new(
        backend: &'a mut F,
        bitwidths: &'a [usize],
        secret_weights_owned: bool,
    ) -> Self {
        Self {
            backend,
            bitwidths,
            secret_weights_owned,
        }
    }
    /// Encode an input so it can be evaluated by a boolean [`NeuralNet`].
    pub(crate) fn encode_input(
        &mut self,
        input: &Array3<i64>,
        channel: &mut Channel,
    ) -> Result<Vec<BinaryBundle<F::Item>>> {
        input
            .iter()
            .map(|&x| {
                let bits = i64_to_twos_complement(x, self.bitwidths[0]);
                self.backend.bin_encode(bits, self.bitwidths[0], channel)
            })
            .collect()
    }

    /// Receive an input so it can be evaluated by a boolean [`NeuralNet`].
    pub(crate) fn receive_input(
        &mut self,
        input: &Array3<i64>,
        channel: &mut Channel,
    ) -> Result<Vec<BinaryBundle<F::Item>>> {
        input
            .iter()
            .map(|_| self.backend.bin_receive(self.bitwidths[0], channel))
            .collect()
    }

    /// Decode a boolean output of a [`NeuralNet`] evaluation.
    pub(crate) fn decode_output(
        &mut self,
        output: &[BinaryBundle<F::Item>],
        channel: &mut Channel,
    ) -> Result<Option<Vec<i64>>> {
        let mut result = Vec::with_capacity(output.len());
        for out in output.iter() {
            let vals = out
                .iter()
                .map(|v| self.backend.output(v, channel))
                .collect::<Result<Vec<_>>>()?;
            let vals = vals.into_iter().collect::<Option<Vec<_>>>();
            let val = vals.map(|vals| i64_from_bits(&vals));
            result.push(val);
        }
        // We need to do the conversion from `Vec<Option>` to `Option<Vec>`
        // _after_ we construct the vector in its entirety, because otherwise
        // it'll short-circuit the execution, causing the garbler to exit out on
        // the first `None`.
        Ok(result.into_iter().collect::<Option<_>>())
    }

    /// Evaluate [`NeuralNet`] as a boolean garbled circuit.
    ///
    /// # Panics
    /// This panics if `bitwidth.len()` does not equal `self.nlayers() + 1`, or
    /// if `circuit_inputs` does not match the dimensions of the input layer.
    pub(crate) fn eval(
        &mut self,
        nn: &NeuralNet,
        circuit_inputs: &[BinaryBundle<F::Item>],
        secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<Vec<BinaryBundle<F::Item>>> {
        assert_eq!(
            self.bitwidths.len(),
            nn.layers.len() + 1,
            "`bitwidth.len()` must equal `self.nlayers() + 1`"
        );

        // Map the user-provided inputs to the input layer dimensions.
        let mut acc = Array3::from_shape_vec(nn.layers[0].input_dims(), circuit_inputs.to_vec())
            .wrap_err(
                ErrorKind::InitializationError,
                "Failed to initialize input layer",
            )?;

        // Evaluate the neural net layer-by-layer.
        for (i, layer) in nn.layers.iter().enumerate() {
            let mut backend =
                BinaryLayer::new(self.backend, self.bitwidths[i], self.secret_weights_owned);
            acc = layer.eval(&mut backend, acc, secret_weights, channel)?;
        }
        Ok(acc.into_raw_vec())
    }
}

pub struct BinaryLayer<'a, F> {
    backend: &'a mut F,
    nbits: usize,
    secret_weights_owned: bool,
}

impl<'a, F: BinaryGadgets> BinaryLayer<'a, F> {
    pub(crate) fn new(backend: &'a mut F, nbits: usize, secret_weights_owned: bool) -> Self {
        Self {
            backend,
            nbits,
            secret_weights_owned,
        }
    }
}

impl<'a, F: Fancy + BinaryGadgets> FancyNeuralNet for BinaryLayer<'a, F> {
    type Item = BinaryBundle<F::Item>;

    fn nn_encode(&mut self, value: i64, channel: &mut Channel) -> Result<BinaryBundle<F::Item>> {
        let twos = i64_to_twos_complement(value, self.nbits);
        self.backend.bin_constant_bundle(twos, self.nbits, channel)
    }

    fn nn_secret(
        &mut self,
        value: Option<i64>,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<F::Item>> {
        if self.secret_weights_owned {
            let xbits = i64_to_twos_complement(value.unwrap(), self.nbits);
            self.backend.bin_encode(xbits, self.nbits, channel)
        } else {
            self.backend.bin_receive(self.nbits, channel)
        }
    }

    fn nn_add(
        &mut self,
        x: &BinaryBundle<F::Item>,
        y: &BinaryBundle<F::Item>,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<F::Item>> {
        self.backend.bin_addition_no_carry(x, y, channel)
    }

    fn nn_cmul(
        &mut self,
        x: &BinaryBundle<F::Item>,
        constant: i64,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<F::Item>> {
        self.backend
            .bin_cmul(x, constant as u128, self.nbits, channel)
    }

    fn nn_proj(
        &mut self,
        x: &BinaryBundle<F::Item>,
        tt: Option<i64>,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<F::Item>> {
        // ignore the input weight - it needs to be a garbler input
        let weight_bits = tt.map(|w| i64_to_twos_complement(w, self.nbits));
        let w = if self.secret_weights_owned {
            self.backend
                .bin_encode(weight_bits.unwrap(), self.nbits, channel)?
        } else {
            self.backend.bin_receive(self.nbits, channel)?
        };
        self.backend.bin_multiplication_lower_half(x, &w, channel)
    }

    fn nn_max(
        &mut self,
        xs: &[BinaryBundle<F::Item>],
        channel: &mut Channel,
    ) -> Result<BinaryBundle<F::Item>> {
        self.backend.bin_max(xs, channel)
    }

    fn nn_activation(
        &mut self,
        f: &ActivationFunction,
        x: &BinaryBundle<F::Item>,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<F::Item>> {
        match f {
            ActivationFunction::Sign => {
                let sign = x.wires().last().unwrap();
                let neg1 = (1 << self.nbits) - 1;
                self.backend
                    .bin_multiplex_constant_bits(sign, 1, neg1, self.nbits, channel)
            }
            ActivationFunction::Relu => {
                let sign = x.wires().last().unwrap();
                let zeros = self
                    .backend
                    .bin_constant_bundle(0u128, self.nbits, channel)?;
                self.backend.bin_multiplex(sign, x, &zeros, channel)
            }
            ActivationFunction::Identity => Ok(x.clone()),
        }
    }

    fn nn_zero(&mut self, channel: &mut Channel) -> Result<BinaryBundle<F::Item>> {
        self.backend.bin_constant_bundle(0u128, self.nbits, channel)
    }
}

use crate::{
    ActivationFunction,
    layer::Layer,
    neural_net::{FancyNeuralNet, NeuralNetExecutor},
};
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::Result;

pub(crate) struct LayerConvolutional {
    /// The filter weights.
    pub(crate) filters: Vec<Array3<Option<i64>>>,
    /// The layer biases.
    pub(crate) biases: Vec<Option<i64>>,
    /// The input dimensions, given as (height, width, depth).
    pub(crate) input_shape: (usize, usize, usize),
    /// The kernel dimensions, given as (height, width, depth).
    pub(crate) kernel_shape: (usize, usize, usize),
    /// The stride, given as (y, x).
    pub(crate) stride: (usize, usize),
    /// The activation type.
    pub(crate) activation: ActivationFunction,
    /// Whether to apply padding or not.
    pub(crate) pad: bool,
}

impl core::fmt::Display for LayerConvolutional {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Convolutional")
    }
}

impl core::fmt::Debug for LayerConvolutional {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Conv[{}] activation={} stride={:?} kernel_shape={:?}",
            self.filters.len(),
            self.activation,
            self.stride,
            self.kernel_shape,
        )
    }
}

impl Layer for LayerConvolutional {
    fn input_dims(&self) -> (usize, usize, usize) {
        self.input_shape
    }

    fn output_dims(&self) -> (usize, usize, usize) {
        let (height, width, _) = self.input_shape;
        let (ker_height, ker_width, _) = self.kernel_shape;
        let (stride_y, stride_x) = self.stride;

        if self.pad {
            (height, width, self.filters.len())
        } else {
            (
                (height - ker_height) / stride_y + 1,
                (width - ker_width) / stride_x + 1,
                self.filters.len(),
            )
        }
    }
}

impl<F: FancyNeuralNet> NeuralNetExecutor<F> for LayerConvolutional {
    fn execute(
        &self,
        backend: &mut F,
        inputs: Array3<F::Item>,
        secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<Array3<F::Item>> {
        let mut output: Array3<Option<_>> = Array3::default(self.output_dims());

        let (height, width, _) = self.input_shape;
        let (kheight, kwidth, kdepth) = self.kernel_shape;
        let (stride_y, stride_x) = self.stride;

        let zero_rows = if self.pad {
            (stride_y - 1) * height + kheight - stride_y
        } else {
            0
        };
        let zero_cols = if self.pad {
            (stride_x - 1) * width + kwidth - stride_x
        } else {
            0
        };

        let shift_y = ((zero_rows as f32) / 2.0).floor() as usize;
        let shift_x = ((zero_cols as f32) / 2.0).floor() as usize;

        for filterno in 0..self.filters.len() {
            let mut h = 0;
            while stride_y * h <= height - kheight + zero_rows {
                let mut w = 0;
                while stride_x * w <= width - kwidth + zero_cols {
                    let mut x = if secret_weights {
                        backend.nn_secret(self.biases[filterno], channel)?
                    } else {
                        backend.nn_encode(
                            self.biases[filterno].expect("biases required for evaluation"),
                            channel,
                        )?
                    };

                    for i in 0..kheight {
                        let idx_y = stride_y * h + i;
                        for j in 0..kwidth {
                            let idx_x = stride_x * w + j;
                            for k in 0..kdepth {
                                let pad_condition = self.pad
                                    && ((idx_y < shift_y || idx_x < shift_x)
                                        || (idx_y >= height + shift_y || idx_x >= width + shift_x));

                                let input_val = if pad_condition {
                                    &backend.nn_zero(channel)?
                                } else {
                                    &inputs[(idx_y - shift_y, idx_x - shift_x, k)]
                                };

                                let prod = if secret_weights {
                                    backend.nn_proj(
                                        input_val,
                                        self.filters[filterno][(i, j, k)],
                                        channel,
                                    )?
                                } else {
                                    backend.nn_cmul(
                                        input_val,
                                        self.filters[filterno][(i, j, k)]
                                            .expect("weights required for evaluation"),
                                        channel,
                                    )?
                                };
                                x = backend.nn_add(&x, &prod, channel)?;
                            }
                        }
                    }

                    let z = backend.nn_activation(&self.activation, &x, channel)?;
                    assert!(output[(h, w, filterno)].is_none());
                    output[(h, w, filterno)] = Some(z);
                    w += 1;
                }
                h += 1;
            }
        }
        Ok(output.mapv(|elem| elem.unwrap()))
    }
}

use crate::{
    layer::Layer,
    neural_net::{FancyNeuralNet, NeuralNetExecutor},
};
use ndarray::Array3;
use swanky_channel::Channel;
use swanky_error::Result;

pub(crate) struct LayerMaxPooling2D {
    /// The input dimensions, given as (height, width, depth).
    pub(crate) input_shape: (usize, usize, usize),
    /// The stride, given as (y, x).
    pub(crate) stride: (usize, usize),
    /// The size, given as (height, width).
    pub(crate) size: (usize, usize),
    /// Whether to apply padding or not.
    pub(crate) pad: bool,
}

impl core::fmt::Display for LayerMaxPooling2D {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MaxPooling2D")
    }
}

impl core::fmt::Debug for LayerMaxPooling2D {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MaxPooling2D stride={:?} size={:?}",
            self.stride, self.size
        )
    }
}

impl Layer for LayerMaxPooling2D {
    fn input_dims(&self) -> (usize, usize, usize) {
        self.input_shape
    }

    fn output_dims(&self) -> (usize, usize, usize) {
        if self.pad {
            self.input_shape
        } else {
            let (height, width, depth) = self.input_shape;
            let (pool_height, pool_width) = self.size;
            let (stride_y, stride_x) = self.stride;

            (
                (height - pool_height) / stride_y + 1,
                (width - pool_width) / stride_x + 1,
                depth,
            )
        }
    }
}

impl<F: FancyNeuralNet> NeuralNetExecutor<F> for LayerMaxPooling2D {
    fn execute(
        &self,
        backend: &mut F,
        inputs: Array3<F::Item>,
        _secret_weights: bool,
        channel: &mut Channel,
    ) -> Result<Array3<F::Item>> {
        let mut output: Array3<Option<_>> = Array3::default(self.output_dims());

        let (height, width, depth) = self.input_shape;
        let (pheight, pwidth) = self.size;
        let (stride_y, stride_x) = self.stride;

        let zero_rows = if self.pad {
            (stride_y - 1) * height + pheight - stride_y
        } else {
            0
        };
        let zero_cols = if self.pad {
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

                            let pad_condition = self.pad
                                && ((idx_y < shift_y || idx_x < shift_x)
                                    || (idx_y >= height + shift_y || idx_x >= width + shift_x));

                            let val = if pad_condition {
                                backend.nn_zero(channel)?.clone()
                            } else {
                                inputs[(idx_y - shift_y, idx_x - shift_x, z)].clone()
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
            let val = backend.nn_max(&window, channel)?;
            output[coordinate] = Some(val);
        }
        Ok(output.mapv(|elem| elem.unwrap()))
    }
}

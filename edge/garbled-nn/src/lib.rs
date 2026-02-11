//! Garbled neural networks using `fancy-garbling`
#![deny(missing_docs)]

mod layer;
mod neural_net;
pub mod util;

pub use layer::{Accuracy, Layer};
pub use neural_net::NeuralNet;

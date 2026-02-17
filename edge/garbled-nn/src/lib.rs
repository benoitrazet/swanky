//! Garbled neural networks using `fancy-garbling`.
#![deny(missing_docs)]

pub mod io;
mod layer;
mod neural_net;
mod util;

pub use layer::{Accuracy, ActivationFunction, Layer};
pub use neural_net::NeuralNet;

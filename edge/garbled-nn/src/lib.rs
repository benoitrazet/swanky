//! Garbled neural networks using `fancy-garbling`.
//!
//! The core type provided by this crate is [`NeuralNet`], which provides an
//! interface for garbling and evaluating neural nets using both boolean and
//! arithmetic garbling.
#![deny(missing_docs)]

pub mod io;
mod layer;
mod neural_net;
mod util;

pub use layer::{Accuracy, ActivationFunction};
pub use neural_net::{InputEncoder, NeuralNet, OutputMap};
pub use util::bitwidths_to_moduli;

//! `fancy-garbling` provides boolean and arithmetic garbling capabilities.
#![allow(non_snake_case)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

mod circuit;
pub use circuit::test_circuits;
mod binary;
pub mod circuit_analyzer;
pub mod circuits;
pub mod classic;
pub mod dummy;
mod fancy;
mod garble;
mod parser;
pub mod util;
mod wire;

pub use crate::{fancy::*, garble::*, wire::*};

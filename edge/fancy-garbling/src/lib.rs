//! `fancy-garbling` provides boolean and arithmetic garbling capabilities.
#![allow(non_snake_case)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

pub mod circuit;
pub mod circuit_analyzer;
pub mod circuits;
pub mod classic;
pub mod dummy;
mod fancy;
mod garble;
pub mod informer;
mod parser;
pub mod util;
mod wire;

pub use crate::{fancy::*, garble::*, wire::*};

#![allow(clippy::all)]
//! `ocelot` provides oblivious transfer, oblivious PRFs and sVOLE extension.
#![allow(clippy::many_single_char_names)]
#![allow(clippy::type_complexity)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

mod utils;
pub use swanky_ocelot_error::Error;
pub mod oprf;
pub mod ot;
pub mod svole;

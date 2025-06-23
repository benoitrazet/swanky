#![allow(clippy::all)]
#![allow(clippy::many_single_char_names)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

//! Scuttlebutt provides many utility functions for cryptographic applications.

/// A polyfill for the `swanky-field*` family of crates.
pub mod field {
    pub use swanky_field::{
        Degree, DegreeModulo, FiniteField, IsSubFieldOf, PrimeFiniteField, field_ops,
    };
    pub use swanky_field_binary::*;
}

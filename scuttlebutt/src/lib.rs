#![allow(clippy::all)]
#![allow(clippy::many_single_char_names)]
#![deny(missing_docs)]
// TODO: when https://git.io/JYTnW gets stabilized add the readme as module docs.

//! Scuttlebutt provides many utility functions for cryptographic applications.

pub use swanky_serialization as serialization;

/// A polyfill for the `swanky-field*` family of crates.
pub mod field {
    pub use swanky_field::{
        Degree, DegreeModulo, FiniteField, IsSubFieldOf, PrimeFiniteField, field_ops,
    };
    pub use swanky_field_binary::*;
    pub use swanky_field_f61p::*;
    pub use swanky_field_ff_primes::*;
    pub use swanky_field_fft as fft;
}
/// A polyfill for the ring functionality inside of `swanky-field`.
pub mod ring {
    pub use swanky_field::{FiniteRing, IsSubRingOf, ring_ops};
}

pub use swanky_aes_rng::{AesRng, UniformIntegersUnderBound};

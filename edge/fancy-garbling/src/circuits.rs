//! Circuits for various operations.

/// Circuits for operating over binary wires.
pub mod binary;

mod linear_oram;
pub use linear_oram::LinearOram;
pub use linear_oram::test::TestLinearOram;

pub mod aes;
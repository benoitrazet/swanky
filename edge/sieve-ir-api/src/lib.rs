//! A Rust based API for writing zero-knowledge circuits in a style compatible with
//! [SIEVE IR](https://github.com/sieve-zk/ir). This provides a programmatic way to write circuits,
//! which should be faster than parsing a circuit dynamically.
//!

#![deny(missing_docs)]

use std::fmt::Debug;
use swanky_error::{ErrorKind, swanky_error};

/// Error types for a SIEVE IR circuit.
pub type CircuitResult<T> = swanky_error::Result<T>;

/// API for field backends that conform to SIEVE IR.
pub trait FieldBackend<F> {
    /// Backend's repesentation for wire values.
    type Wire: Debug + Default + Clone + Copy;

    /// Read a public instance value.
    fn input_public(&mut self) -> CircuitResult<Self::Wire>;

    /// Read multiple public instance values.
    fn inputs_public<const LEN: usize>(&mut self) -> CircuitResult<[Self::Wire; LEN]> {
        // TODO: Use `std::array::try_from_fn` when it's stable.
        let v = (0..LEN)
            .map(|_| self.input_public())
            .collect::<CircuitResult<Vec<Self::Wire>>>()?;
        v.try_into()
            .map_err(|e| swanky_error!(ErrorKind::OtherError, "Conversion error: {e:?}"))
    }

    /// Read a private witness value.
    fn input_private(&mut self) -> CircuitResult<Self::Wire>;

    /// Read multiple private witness values.
    fn inputs_private<const LEN: usize>(&mut self) -> CircuitResult<[Self::Wire; LEN]> {
        // TODO: Use `std::array::try_from_fn` when it's stable.
        let v = (0..LEN)
            .map(|_| self.input_private())
            .collect::<CircuitResult<Vec<Self::Wire>>>()?;
        v.try_into()
            .map_err(|e| swanky_error!(ErrorKind::OtherError, "Conversion error: {e:?}"))
    }

    /// Field addition.
    fn add(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> CircuitResult<Self::Wire>;

    /// Field addition with a constant.
    fn addc(&mut self, lhs: &Self::Wire, rhs: F) -> CircuitResult<Self::Wire>;

    /// Field multiplication.
    fn mul(&mut self, lhs: &Self::Wire, rhs: &Self::Wire) -> CircuitResult<Self::Wire>;

    /// Field multiplication with a constant.
    fn mulc(&mut self, lhs: &Self::Wire, rhs: F) -> CircuitResult<Self::Wire>;

    /// An assertion that the argument is zero.
    fn assert_zero(&mut self, arg: &Self::Wire) -> CircuitResult<()>;
}

/// `CircuitExecuter` abstracts over backends to execute a circuit over a single field type.
/// Note that this is necessary since Rust currently does not support higher order trait bounds. See <https://github.com/rust-lang/rust/issues/108185#issuecomment-2819123578>
pub trait CircuitExecuter<F> {
    /// The body of the circuit to execute, given a backend.
    fn execute<B: FieldBackend<F>>(&self, backend: &mut B) -> CircuitResult<()>;
}

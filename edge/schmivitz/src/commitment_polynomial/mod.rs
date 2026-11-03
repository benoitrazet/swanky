#![doc = include_str!("../../HIGHER_DEGREE_COMMITMENT.md")]

mod commitment_polynomial;

pub mod batch_verification;

use swanky_field_binary::{F2, F128b};

use crate::vole::ExtensionFieldLifterF2F128b;

use batch_verification::{BatchProverAccumulator, BatchVerifierAccumulator};

pub use commitment_polynomial::CommitmentPolynomial;

/// Prover accumulator specialized to `F2`/`F128b` with power-basis lifting.
pub(crate) type BatchProverAccumulatorF2F128b =
    BatchProverAccumulator<F2, F128b, ExtensionFieldLifterF2F128b>;

/// Verifier accumulator specialized to `F2`/`F128b` with power-basis lifting.
pub(crate) type BatchVerifierAccumulatorF2F128b =
    BatchVerifierAccumulator<F2, F128b, ExtensionFieldLifterF2F128b>;

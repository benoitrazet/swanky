#![doc = include_str!("../../HIGHER_DEGREE_COMMITMENT.md")]

mod commitment_polynomial;

pub mod batch_verification;

use swanky_field::FiniteField;
use swanky_field_binary::{F2, F128b};

use crate::vole::ExtensionFieldLifterF2F128b;

use batch_verification::{BatchProverAccumulator, BatchVerifierAccumulator};

pub use commitment_polynomial::{CommitmentPolynomialProver, CommitmentPolynomialVerifier};

/// Compute `base` raised to `exp` in a finite field.
fn power<FE: FiniteField>(base: FE, exp: usize) -> FE {
    let mut result = FE::ONE;
    let mut base = base;
    let mut exp = exp;
    while exp > 0 {
        if exp & 1 == 1 {
            result *= base;
        }
        base *= base;
        exp >>= 1;
    }
    result
}

/// Prover accumulator specialized to `F2`/`F128b` with power-basis lifting.
pub(crate) type BatchProverAccumulatorF2F128b =
    BatchProverAccumulator<F2, F128b, ExtensionFieldLifterF2F128b>;

/// Verifier accumulator specialized to `F2`/`F128b` with power-basis lifting.
pub(crate) type BatchVerifierAccumulatorF2F128b =
    BatchVerifierAccumulator<F2, F128b, ExtensionFieldLifterF2F128b>;

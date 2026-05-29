use crate::{FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

mod pairwise_xor;
pub use pairwise_xor::PairwiseXor;
pub use pairwise_xor::test::TestPairwiseXor;

mod and_many;
pub use and_many::AndMany;
pub use and_many::test::TestAndMany;

mod binary_adder;
pub use binary_adder::BinaryAdder;
pub use binary_adder::test::TestBinaryAdder;

mod binary_addition;
pub use binary_addition::BinaryAddition;
pub use binary_addition::test::TestBinaryAddition;

mod binary_subtraction;
pub use binary_subtraction::BinarySubtraction;
pub use binary_subtraction::test::TestBinarySubtraction;

mod binary_less_than;
pub use binary_less_than::BinaryLessThan;
pub use binary_less_than::test::TestBinaryLessThan;

mod binary_greater_than_or_equal;
pub use binary_greater_than_or_equal::BinaryGreaterThanOrEqual;
pub use binary_greater_than_or_equal::test::TestBinaryGreaterThanOrEqual;

/// Pairwise AND of two bitvectors.
pub struct PairwiseAnd;

impl<F: FancyBinary> Circuit<F> for PairwiseAnd {
    type Input = (Vec<F::Item>, Vec<F::Item>);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        inputs
            .0
            .iter()
            .zip(inputs.1.iter())
            .map(|(x, y)| backend.and(x, y, channel))
            .collect()
    }
}

/// Pairwise OR of two bitvectors.
pub struct PairwiseOr;

impl<F: FancyBinary> Circuit<F> for PairwiseOr {
    type Input = (Vec<F::Item>, Vec<F::Item>);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        inputs
            .0
            .iter()
            .zip(inputs.1.iter())
            .map(|(x, y)| backend.or(x, y, channel))
            .collect()
    }
}

/// Returns `true` if any input is `true`.
///
/// # Panics
/// Panics if no inputs are provided.
pub struct OrMany;

impl<F: FancyBinary> Circuit<F> for OrMany {
    type Input = Vec<F::Item>;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`args` cannot be empty");
        inputs
            .iter()
            .skip(1)
            .try_fold(inputs[0].clone(), |acc, x| backend.or(&acc, x, channel))
    }
}

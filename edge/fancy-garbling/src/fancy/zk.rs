use crate::FancyEncode;
use swanky_channel::Channel;
use swanky_error::Result;

/// Extension trait for [`Fancy`] supporting operations used for zero-knowledge proofs.
pub trait FancyZeroKnowledge: FancyEncode {
    /// Assert that `x == 0`.
    fn assert_zero(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<()>;
}

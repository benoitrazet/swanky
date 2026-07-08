use crate::{EvaluatorOutput, ps::PartyEvaluator};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

/// The evaluator's validation phase.
///
/// This checks that the authenticated shares $`c_\gamma`$ are all valid.
pub struct EvaluatorValidator {
    delta: U8x16,
    validation_shares: Vec<AuthShare<PartyEvaluator>>,
}

impl EvaluatorValidator {
    pub(crate) fn new(delta: U8x16, validation_shares: Vec<AuthShare<PartyEvaluator>>) -> Self {
        Self {
            delta,
            validation_shares,
        }
    }

    /// Validate the computation.
    pub fn validate(self, channel: &mut Channel) -> Result<EvaluatorOutput> {
        let mut validation_bits = Vec::with_capacity(self.validation_shares.len());
        // The parties then open the share c_γ
        AuthShareGenerator::open_with_delta(
            &self.validation_shares,
            self.delta,
            &mut validation_bits,
            channel,
        )?;
        let validation_failures: Vec<&F2> =
            validation_bits.iter().filter(|&&x| x == F2::ONE).collect();
        swanky_error::ensure!(
            validation_failures.is_empty(),
            ErrorKind::OtherError,
            "Evaluator's authentication validation check failed"
        );
        Ok(EvaluatorOutput::new(self.delta))
    }
}

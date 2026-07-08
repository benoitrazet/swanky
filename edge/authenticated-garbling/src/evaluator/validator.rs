use fancy_traits::{Fancy, FancyOutput};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

use crate::{evaluator::AuthenticatedWire, ps::PartyEvaluator};

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
    pub fn validate(self, channel: &mut Channel) -> Result<Self> {
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
        Ok(self)
    }
}

impl Fancy for EvaluatorValidator {
    type Item = AuthenticatedWire;

    fn constant(&mut self, _: u16, _: u16, _: &mut Channel) -> Result<Self::Item> {
        // TODO: `constant` should _not_ be a part of `Fancy`, but maybe live in
        // a `FancyConstant` trait?
        unimplemented!(
            "In the validation phase, we don't do any circuit evaluation, so `constant should never be called."
        )
    }
}

impl FancyOutput for EvaluatorValidator {
    fn output(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Option<u16>> {
        Ok(self
            .outputs(core::slice::from_ref(x), channel)?
            .map(|xs| xs[0]))
    }

    fn outputs(&mut self, x: &[Self::Item], channel: &mut Channel) -> Result<Option<Vec<u16>>> {
        let auth_shares = x.iter().map(|wire| wire.auth_share()).collect::<Vec<_>>();
        let mut masks = Vec::with_capacity(x.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &auth_shares,
            self.delta,
            &mut masks,
            channel,
        )?;
        let outputs = masks
            .into_iter()
            .zip(x)
            .map(|(mask, out)| (mask + out.masked_value() + out.auth_share().bit()).into())
            .collect::<Vec<_>>();
        Ok(Some(outputs))
    }
}

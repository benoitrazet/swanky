use fancy_traits::{Fancy, FancyOutput};
use swanky_authenticated_bits::authshares::AuthShareGenerator;
use swanky_channel::Channel;
use swanky_error::Result;

use crate::wire::OfflineWire;

/// The garbler's output phase.
pub struct GarblerOutput {}

impl GarblerOutput {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl Fancy for GarblerOutput {
    type Item = OfflineWire;

    fn constant(&mut self, _: u16, _: u16, _: &mut Channel) -> Result<Self::Item> {
        // TODO: `constant` should _not_ be a part of `Fancy`, but maybe live in
        // a `FancyConstant` trait?
        unimplemented!(
            "In the output phase, we don't do any circuit evaluation, so `constant` should never be called."
        )
    }
}

impl FancyOutput for GarblerOutput {
    fn output(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Option<u16>> {
        Ok(self
            .outputs(core::slice::from_ref(x), channel)?
            .map(|xs| xs[0]))
    }

    fn outputs(&mut self, x: &[Self::Item], channel: &mut Channel) -> Result<Option<Vec<u16>>> {
        let auth_shares = x.iter().map(|wire| wire.auth_share()).collect::<Vec<_>>();
        AuthShareGenerator::open_my_shares(&auth_shares, channel)?;
        Ok(None)
    }
}

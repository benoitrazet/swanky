use crate::{AuthenticatedWireMod2, ps::PartyGarbler, vec_wrapper::VecWrapper};
use fancy_garbling::{CircuitInputMapper, Fancy, FancyBinary, FancyOutput, WireLabel, WireMod2};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;
/// A struct which allows the garbler to compute the validation shares before opening them
pub struct GarblerValidator {
    // The garbler's Δ.
    delta: WireMod2,
    // A vector of authenticated shares, one per input wire and AND gate output.
    // Corresponds to〈r_w, s_w〉from the paper.
    auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
    // A vector of fixed authenticated shares for AND gate wires. Each share is
    // set such that it is equal to the AND of the incoming wire shares.
    // Corresponds to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
    validation_shares: Vec<AuthShare<PartyGarbler>>,
    // A vector that stores the masked wire values received from the evaluator.
    lc_values: VecWrapper<F2>,
}

impl GarblerValidator {
    /// Create a new [`GarblerValidator`] from a reference to the [`Garbler`]
    /// and from the masked wire values received from the evaluator
    pub(crate) fn new(
        delta: WireMod2,
        mut auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
        mut and_auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
        ninputs: usize,
        lc_values: Vec<F2>,
    ) -> GarblerValidator {
        auth_shares.set_index(ninputs);
        and_auth_shares.reset();
        GarblerValidator {
            delta,
            auth_shares,
            and_auth_shares,
            validation_shares: Vec::new(),
            lc_values: VecWrapper::new(lc_values),
        }
    }

    pub(crate) fn validate<C: CircuitInputMapper<Self>>(
        mut self,
        circuit: &C,
        inputs: Vec<AuthenticatedWire>,
        channel: &mut Channel,
    ) -> Result<Self> {
        // Locally run the circuit to correctly construct the validation shares
        Channel::with(std::io::empty(), {
            |c| circuit.execute(&mut self, circuit.map(inputs), c)
        })?;

        let mut validation_bits = Vec::with_capacity(self.and_auth_shares.len());
        // The parties then open the share c_γ
        AuthShareGenerator::open_with_delta(
            &self.validation_shares,
            self.delta(),
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

    fn delta(&self) -> U8x16 {
        self.delta.to_repr()
    }
}

impl Fancy for GarblerValidator {
    type Item = AuthenticatedWire;
    fn constant(
        &mut self,
        value: u16,
        _q: u16,
        _channel: &mut Channel,
    ) -> swanky_error::Result<AuthenticatedWire> {
        let constant = F2::try_from(value).expect("constant must be boolean");
        let auth_share = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta());

        Ok(AuthenticatedWire::new_without_label(constant, auth_share))
    }
}

impl FancyBinary for GarblerValidator {
    fn and(
        &mut self,
        la0: &Self::Item,
        lb0: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // This is the share for wire label L_{γ,0}
        let lc_share = self.auth_shares.next();
        // This is the and triple share for wire label L_{γ,0}
        let lc_triple = self.and_auth_shares.next();

        let lc_value = self.lc_values.next();
        // z'α := z_α + λ_α, where z_α is the actual wire value of the input
        // wire with label L_α and λ_α is the mask of that value
        let la_value = la0.masked_value();
        // The Garbler's authenticated share of λ_α
        let la_lambda = la0.auth_share();
        // z'β := z_β + λ_β, where z_β is the actual wire value of the input
        // wire with label L_β and λ_β is the mask of that value
        let lb_value = lb0.masked_value();
        // The Garbler's authenticated share of λ_β
        let lb_lambda = lb0.auth_share();

        // The Garbler first creates the constant share of (z'α z'β ⊕ z'γ )
        let share_masks =
            AuthShareGenerator::constant_with_delta(la_value * lb_value + lc_value, self.delta());
        // Then they create their share of the validation bit
        // c_γ := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)
        self.validation_shares.push(
            share_masks
                ^ la_lambda.mul_with_const(lb_value)
                ^ lb_lambda.mul_with_const(la_value)
                ^ lc_triple
                ^ lc_share,
        );
        Ok(AuthenticatedWire::new_without_label(lc_value, lc_share))
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        AuthenticatedWire::new_without_label(
            x.masked_value() + y.masked_value(),
            x.auth_share() ^ y.auth_share(),
        )
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWire::new_without_label(x.masked_value() + F2::ONE, x.auth_share())
    }
}

impl FancyOutput for GarblerValidator {
    fn output(&mut self, x: &AuthenticatedWire, channel: &mut Channel) -> Result<Option<u16>> {
        Ok(self
            .outputs(core::slice::from_ref(x), channel)?
            .map(|xs| xs[0]))
    }

    fn outputs(
        &mut self,
        x: &[AuthenticatedWire],
        channel: &mut Channel,
    ) -> Result<Option<Vec<u16>>> {
        let auth_shares = x.iter().map(|wire| wire.auth_share()).collect::<Vec<_>>();
        AuthShareGenerator::open_my_shares(&auth_shares, channel)?;
        Ok(None)
    }
}

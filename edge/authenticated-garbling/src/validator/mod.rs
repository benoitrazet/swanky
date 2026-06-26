use fancy_garbling::{Fancy, FancyBinary, FancyEncode};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

use crate::{AuthenticatedWireMod2, Garbler, ps::PartyGarbler, vec_wrapper::VecWrapper};

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;
/// A struct which allows the garbler to compute the validation shares before opening them
pub struct GarblerValidator {
    gb: Garbler,
    validation_shares: Vec<AuthShare<PartyGarbler>>,
    // A vector that stores the masked wire values received from the evaluator.
    lc_values: VecWrapper<F2>,
    // The input wires computed by the garbler in the offline phase
    input_wires: VecWrapper<AuthenticatedWire>,
}

impl GarblerValidator {
    /// Create a new [`GarblerValidator`] from a reference to the [`Garbler`]
    /// and from the masked wire values received from the evaluator
    pub fn new(
        mut gb: Garbler,
        input_wires: Vec<AuthenticatedWire>,
        lc_values: Vec<F2>,
    ) -> GarblerValidator {
        gb.auth_shares.set_index(input_wires.len());
        gb.and_auth_shares.reset();
        GarblerValidator {
            gb,
            validation_shares: Vec::new(),
            lc_values: VecWrapper::new(lc_values),
            input_wires: VecWrapper::new(input_wires),
        }
    }

    /// Return the computed validation shares that be opened and authenticated
    pub fn validation_shares(&self) -> &[AuthShare<PartyGarbler>] {
        &self.validation_shares
    }

    fn delta(&self) -> U8x16 {
        self.gb.delta()
    }
    /// Return the garbler's state
    pub fn garbler(self) -> Garbler {
        self.gb
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
        let lc_share = self.gb.auth_shares.next();
        // This is the and triple share for wire label L_{γ,0}
        let lc_triple = self.gb.and_auth_shares.next();

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

impl FancyEncode for GarblerValidator {
    fn receive_many(
        &mut self,
        moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        Ok((0..moduli.len()).map(|_| self.input_wires.next()).collect())
    }

    fn encode_many(
        &mut self,
        _values: &[u16],
        moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        Ok((0..moduli.len()).map(|_| self.input_wires.next()).collect())
    }
}

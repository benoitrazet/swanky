use fancy_garbling::{
    Fancy, FancyBinary, FancyEncode, FancyOutput, HasModulus, WireLabel, WireMod2,
};
use rand::{CryptoRng, RngCore};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F128b};
use swanky_party::GenericParty;
use vectoreyes::U8x16;

use crate::{
    AuthenticatedWireMod2, Garbler,
    ps::{Party, PartyGarbler},
};

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;
#[derive(Clone, Copy)]
pub struct FinalizedWire {
    /// Masked value $`w \oplus \lambda`$.
    masked_value: F2,
    /// Sharing of the color bit $`\lambda`$.
    auth_share: AuthShare<PartyGarbler>,
}

impl core::fmt::Debug for FinalizedWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizedWire")
            .field("auth_share", &())
            .finish()
    }
}

impl FinalizedWire {
    /// Construct a new [`FinalizedWire`] from an authenticated share.
    pub(crate) fn new(masked_value: F2, auth_share: AuthShare<PartyGarbler>) -> Self {
        FinalizedWire {
            masked_value,
            auth_share,
        }
    }
    /// The masked value associated with this wire.
    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value
    }
    /// The authenticated share $`\langle \lambda \rangle`$ associated with this
    /// wire.
    pub(crate) fn auth_share(&self) -> AuthShare<PartyGarbler> {
        self.auth_share
    }
}

impl HasModulus for FinalizedWire {
    fn modulus(&self) -> u16 {
        2
    }
}
/// A struct which allows the garbler to compute the validation shares before opening them
pub struct GarblerFinalizer<'a, RNG> {
    gb: &'a Garbler<RNG>,
    validation_shares: Vec<AuthShare<PartyGarbler>>,
    // A vector that stores the masked wire values received from the evaluator.
    lc_values: Vec<F2>,
    // The index of the current masked wire value we're using.
    lc_values_index: usize,
    // The index of the current authenticated share we're using.
    auth_shares_index: usize,
    // The index of the current AND authenticated share we're using.
    and_auth_shares_index: usize,
    // The input wires computed by the garbler in the offline phase
    input_wires: Vec<FinalizedWire>,
    // The index of the current input wire
    input_wires_index: usize,
}

impl<'a, RNG: CryptoRng + RngCore> GarblerFinalizer<'a, RNG> {
    /// Create a new [`GarblerFinalizer`] from a reference to the [`Garbler`]
    /// and from the masked wire values received from the evaluator
    pub fn new<'b>(
        gb: &'b Garbler<RNG>,
        input_wires: Vec<FinalizedWire>,
    ) -> GarblerFinalizer<'b, RNG> {
        GarblerFinalizer {
            gb,
            validation_shares: Vec::new(),
            lc_values: Vec::new(),
            lc_values_index: 0,
            auth_shares_index: input_wires.len(),
            and_auth_shares_index: 0,
            input_wires,
            input_wires_index: 0,
        }
    }
    /// Set the lc values once they are received.
    pub fn set_lc_values(&mut self, lc_values: Vec<F2>) -> Result<()> {
        self.lc_values.extend(lc_values);
        Ok(())
    }
    /// Return the computed validation shares that be opened and authenticated
    pub fn validation_shares(&self) -> &[AuthShare<PartyGarbler>] {
        &self.validation_shares
    }
    fn next_auth_share(&mut self) -> AuthShare<PartyGarbler> {
        let share = self.gb.auth_share_at_index(self.auth_shares_index);
        self.auth_shares_index += 1;
        share
    }

    fn next_and_auth_share(&mut self) -> AuthShare<PartyGarbler> {
        let share = self.gb.and_auth_share_at_index(self.and_auth_shares_index);
        self.and_auth_shares_index += 1;
        share
    }

    fn next_lc_value(&mut self) -> F2 {
        let lc_value = self.lc_values[self.lc_values_index];
        self.lc_values_index += 1;
        lc_value
    }
    fn delta(&self) -> U8x16 {
        self.gb.delta()
    }
}
impl<'a, RNG> Fancy for GarblerFinalizer<'a, RNG>
where
    RNG: RngCore + CryptoRng,
{
    type Item = FinalizedWire;
    fn constant(
        &mut self,
        value: u16,
        _q: u16,
        _channel: &mut Channel,
    ) -> swanky_error::Result<FinalizedWire> {
        let constant = F2::try_from(value).expect("constant must be boolean");
        let auth_share = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta());

        Ok(FinalizedWire::new(constant, auth_share))
    }
}

impl<'a, RNG> FancyBinary for GarblerFinalizer<'a, RNG>
where
    RNG: RngCore + CryptoRng,
{
    fn and(
        &mut self,
        la0: &Self::Item,
        lb0: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // This is the share for wire label L_{γ,0}
        let lc_share = self.next_auth_share();
        // This is the and triple share for wire label L_{γ,0}
        let lc_triple = self.next_and_auth_share();

        let lc_value = self.next_lc_value();
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
        Ok(FinalizedWire::new(lc_value, lc_share))
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        FinalizedWire::new(
            x.masked_value() + y.masked_value(),
            x.auth_share() ^ y.auth_share(),
        )
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        FinalizedWire::new(x.masked_value() + F2::ONE, x.auth_share())
    }
}

impl<'a, RNG> FancyEncode for GarblerFinalizer<'a, RNG>
where
    RNG: RngCore + CryptoRng,
{
    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let start = self.input_wires_index;
        self.input_wires_index += moduli.len();
        Ok(self.input_wires[start..moduli.len()].to_vec())
    }

    fn encode_many(
        &mut self,
        _values: &[u16],
        moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let start = self.input_wires_index;
        self.input_wires_index += moduli.len();
        Ok(self.input_wires[start..moduli.len()].to_vec())
    }
}

impl<'a, RNG> FancyOutput for GarblerFinalizer<'a, RNG>
where
    RNG: RngCore + CryptoRng,
{
    fn output(&mut self, _: &Self::Item, _: &mut Channel) -> swanky_error::Result<Option<u16>> {
        Ok(None)
    }
}

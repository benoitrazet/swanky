//! Evaluator for Authenticated Garbling

use fancy_garbling::{
    Fancy, FancyBinary, WireLabel, WireMod2, circuit::CircuitExecutor,
    circuit_analyzer::CircuitAnalyzer,
};
use rand::{CryptoRng, RngCore};
use swanky_authenticated_bits::{
    and_triples::AndTripleGenerator,
    authshares::{AuthShare, AuthShareGenerator},
};
use swanky_channel::Channel;

use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F128b};
use vectoreyes::U8x16;

use crate::{
    preprocesser::{f_preprocessing, wire::WirePreProcessor},
    ps::PartyEvaluator,
    wire::AuthenticatedWireMod2,
};

type AuthenticatedWire = AuthenticatedWireMod2<PartyEvaluator>;

/// The authenticated evaluator.
pub struct Evaluator<RNG> {
    one: WireMod2,
    authentication_delta: U8x16,
    current_wire_index: usize,
    auth_shares: Vec<AuthShare<PartyEvaluator>>,
    auth_shares_index: usize,
    known_triples: Vec<AuthShare<PartyEvaluator>>,
    known_triples_index: usize,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Evaluator<RNG> {
    /// Create a new `Evaluator`.
    pub fn new(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self> {
        // Receive the constant one wirelabel from the garbler. This is used to
        // make negation free.
        let authentication_delta =
            AndTripleGenerator::<PartyEvaluator>::generate_valid_delta(&mut rng);
        let one = channel.read::<U8x16>()?;
        Ok(Evaluator {
            one: WireMod2::from_repr(one, 2),
            authentication_delta,
            auth_shares: Vec::new(),
            auth_shares_index: 0,
            known_triples: Vec::new(),
            known_triples_index: 0,
            current_wire_index: 0,
            rng,
        })
    }

    /// Pre-process the passed circuit
    pub fn preprocess_circuit<
        C: CircuitExecutor<CircuitAnalyzer> + CircuitExecutor<WirePreProcessor<PartyEvaluator>>,
    >(
        &mut self,
        circuit: &C,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        let mut and_generator =
            AndTripleGenerator::new_with_delta(self.delta(), channel, &mut self.rng)?;
        let (auth_shares, known_triples) =
            f_preprocessing(circuit, &mut and_generator, channel, &mut self.rng)?;
        self.auth_shares = auth_shares;
        self.known_triples = known_triples;
        Ok(())
    }
    /// Get the deltas, consuming the Evaluator
    pub fn delta(&self) -> U8x16 {
        self.authentication_delta
    }
    /// The current output index of the garbling computation.
    fn current_wire_index(&mut self) -> usize {
        let current = self.current_wire_index;
        self.current_wire_index += 1;
        current
    }

    fn get_next_auth_share(&mut self) -> AuthShare<PartyEvaluator> {
        let share = self.auth_shares[self.auth_shares_index];
        self.auth_shares_index += 1;
        share
    }

    fn get_next_known_triple(&mut self) -> AuthShare<PartyEvaluator> {
        let share = self.known_triples[self.known_triples_index];
        self.known_triples_index += 1;
        share
    }
}

impl<RNG: CryptoRng + RngCore> FancyBinary for Evaluator<RNG> {
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2::new_with_value(
            x.masked_value() + F2::from(1),
            WireMod2::from_repr(x.wire_label().to_repr() ^ self.one.to_repr(), 2),
            x.auth_share(),
            x.index(),
        )
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2::new_with_value(
            x.masked_value() + y.masked_value(),
            x.wire_label() + y.wire_label(),
            x.auth_share() ^ y.auth_share(),
            self.current_wire_index(),
        )
    }

    fn and(
        &mut self,
        la: &Self::Item,
        lb: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // This index is called γ in the paper
        let index = self.current_wire_index();
        // This is the current wire's authenticated share
        let lc_share = self.get_next_auth_share();
        // This is the current wire's authenticated triple
        let lc_triple = self.get_next_known_triple();

        // This is the MAC associated with the current wire's authenticated share: M[s_γ]
        let mac_share = lc_share.mac();
        // This is the MAC associated with the current wire's authenticated triple: M[s*_γ]
        let mac_triple = lc_triple.mac();

        // This is the value: Gate_{γ,0}
        let gate_c0: U8x16 = channel.read()?;
        // This is the value: Gate_{γ,1}
        let gate_c1: U8x16 = channel.read()?;
        // This is the value: b_γ
        let bit_c: F2 = channel.read()?;

        // This is the value: Gate_0 = Gate_{γ,0} + M[s_β]
        let gate0 = gate_c0 ^ lb.auth_share().mac();
        // This is the value: Gate_1 = Gate_{γ,1} + M[s_α]
        let gate1 = gate_c1 ^ la.auth_share().mac();

        // This is the value H(L_{α, z_α + λ_α}, γ)
        let h_la = la.wire_label().hash(index as u128);
        // This is the value H(L_{β, z_β + λ_β}, γ)
        let h_lb = lb.wire_label().hash(index as u128);

        // z'α := z_α + λ_α, where z_α is the actual wire value of the input
        // wire with label L_α and λ_α is the mask of that value
        let la_value = la.masked_value();
        // The Evaluator's authenticated share of λ_α
        let la_lambda = la.auth_share();
        // z'β := z_β + λ_β, where z_β is the actual wire value of the input
        // wire with label L_β and λ_β is the mask of that value
        let lb_value = lb.masked_value();
        // The Evaluator's authenticated share of λ_β
        let lb_lambda = lb.auth_share();

        // This is the value (z_α + λ_α)Gate_0
        let gate0_muxed = U8x16::from(la_value * F128b::from(gate0));
        // This is the value (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let gate1_muxed = U8x16::from(lb_value * F128b::from(gate1 ^ la.wire_label().to_repr()));

        // This the value:
        //  L_{γ, z_γ + λ_γ} := H(L_{α, z_α + λ_α}, γ) + H(L_{β, z_β + λ_β}, γ) + M[s_γ]
        //                      + M[s*_γ] + (z_α + λ_α)Gate_0 + (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let lc_label = h_la ^ h_lb ^ mac_share ^ mac_triple ^ gate0_muxed ^ gate1_muxed;

        // The current masked value of the wire is:
        // z'γ := z_γ + λ_γ := b_γ + lsb(L_{γ, z_γ + λ_γ})
        let lc_value = F128b::from(lc_label).lsb() + bit_c;

        // The Evaluator sends out the masked bit z'γ so that the Garbler
        // can locally compute their share of c_γ
        channel.write(&lc_value)?;

        // The Evaluator computes its share of the validation bit
        // c_γ :=  (z'α ⊕ λ_α) ∧ (z'β ⊕ λ_β ) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'β λ_α ⊕ z'α λ_β ⊕ λ_α λ_β) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)

        // The Evaluator first creates the constant share of (z'α z'β ⊕ z'γ )
        let share_masks: AuthShare<PartyEvaluator> =
            AuthShareGenerator::constant_with_delta(la_value * lb_value + lc_value, self.delta());
        // Then they create their share of the validation bit
        // c_γ := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)
        let validation_share = share_masks
            ^ la_lambda.mul_with_const(lb_value)
            ^ lb_lambda.mul_with_const(la_value)
            ^ lc_triple
            ^ lc_share;

        let mut validation_bit = Vec::with_capacity(1);
        // The parties then open the share c_γ
        AuthShareGenerator::open_with_delta(
            &[validation_share],
            self.delta(),
            &mut validation_bit,
            channel,
        )?;

        assert_eq!(
            validation_bit[0],
            F2::ZERO,
            "Evaluator's authentication validation check failed at index {index}"
        );

        Ok(AuthenticatedWireMod2::new_with_value(
            lc_value,
            WireMod2::from_repr(lc_label, 2),
            lc_share,
            index,
        ))
    }
}

impl<RNG: CryptoRng + RngCore> Fancy for Evaluator<RNG> {
    type Item = AuthenticatedWire;

    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        // The Evaluator retrieves authenticated shares for their own inputs.
        let mut indices = Vec::with_capacity(values.len());
        let my_auth_shares: Vec<AuthShare<PartyEvaluator>> = (0..moduli.len())
            .map(|_i| {
                let index = self.current_wire_index();
                indices.push(index);
                self.get_next_auth_share()
            })
            .collect();

        let mut their_bits = Vec::with_capacity(moduli.len());
        // The Evaluator opens and receives the garblers share [r_w].
        // Because this is effectively being used to compute the
        // Evaluator's input labels, we use the Evaluator's
        // authenticated shares
        AuthShareGenerator::open_their_shares_with_delta(
            &my_auth_shares,
            self.delta(),
            &mut their_bits,
            channel,
        )
        .unwrap();

        // TODO: Change how the evaluator retrieves their values and possibly
        // move this part all together when we refactor EV/GB
        let mut my_masked_values: Vec<F2> = Vec::with_capacity(values.len());
        for (i, b) in their_bits.iter().enumerate() {
            // Evaluator computes their masked values y_w + λ_w := y_w ⊕ s_w ⊕
            // r_w
            let masked_value = b + my_auth_shares[i].bit() + F2::from(values[i]);
            my_masked_values.push(masked_value);

            // Evaluator sends y_w + λ_w  to the Garbler
            channel.write(&masked_value)?;
        }

        let mut my_auth_wires: Vec<AuthenticatedWire> = Vec::with_capacity(values.len());

        for (i, masked_value) in my_masked_values.iter().enumerate() {
            // The Evaluator retrieves the wire labels for their own input
            let wire_label = WireMod2::from_repr(channel.read()?, 2);
            // The Evaluator constructs authenticated values for all their input wires
            my_auth_wires.push(AuthenticatedWireMod2::new_with_value(
                *masked_value,
                wire_label,
                my_auth_shares[i],
                indices[i],
            ));
        }

        Ok(my_auth_wires)
    }

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        // The Evaluator retrieves authenticated shares for the garbler's inputs.
        let mut indices = Vec::with_capacity(moduli.len());
        let their_auth_shares: Vec<AuthShare<PartyEvaluator>> = (0..moduli.len())
            .map(|_i| {
                let index = self.current_wire_index();
                indices.push(index);
                self.get_next_auth_share()
            })
            .collect();

        AuthShareGenerator::open_my_shares(&their_auth_shares, channel)?;

        let mut their_auth_wires: Vec<AuthenticatedWire> = Vec::with_capacity(moduli.len());

        // The Evaluator receives the wire labels and masked values of the Garbler and uses these values
        // to construct the garbler's authenticated wires
        for (i, share) in indices.into_iter().zip(their_auth_shares) {
            let their_wire_label = WireMod2::from_repr(channel.read()?, 2);
            let their_masked_value = channel.read()?;
            their_auth_wires.push(AuthenticatedWireMod2::new_with_value(
                their_masked_value,
                their_wire_label,
                share,
                i,
            ));
        }

        Ok(their_auth_wires)
    }

    fn constant(
        &mut self,
        value: u16,
        _q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<AuthenticatedWire> {
        // We haven't implemented a way to take advantage of constant wires
        // in FancyBinary. So they need to be treated as input wires.
        let index = self.current_wire_index();
        let current_share = self.get_next_auth_share();

        let my_masked_value = current_share.bit();
        let mut their_masked_value = Vec::with_capacity(1);

        AuthShareGenerator::open_their_shares_with_delta(
            &[current_share],
            self.delta(),
            &mut their_masked_value,
            channel,
        )?;
        let masked_value = F2::from(value) + their_masked_value[0] + my_masked_value;
        channel.write(&masked_value)?;
        let wire_label = WireMod2::from_repr(channel.read().unwrap(), 2);

        Ok(AuthenticatedWireMod2::new_with_value(
            masked_value,
            wire_label,
            current_share,
            index,
        ))
    }

    fn output(
        &mut self,
        x: &AuthenticatedWire,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        let auth_share: AuthShare<PartyEvaluator> = x.auth_share();
        let mut out = Vec::with_capacity(1);
        AuthShareGenerator::open_with_delta(&[auth_share], self.delta(), &mut out, channel)?;
        Ok(Some(u16::from(out[0])))
    }
    // Preferable function when processing multiple outputs!
    // It can efficiently batch opening bits.
    fn outputs(
        &mut self,
        x: &[AuthenticatedWire],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u16>>> {
        let auth_shares: Vec<AuthShare<PartyEvaluator>> =
            x.iter().map(|wire| wire.auth_share()).collect();
        let mut masks = Vec::with_capacity(x.len());
        AuthShareGenerator::open_with_delta(&auth_shares, self.delta(), &mut masks, channel)?;
        let mut outputs = Vec::with_capacity(x.len());
        for i in 0..x.len() {
            outputs.push((masks[i] + x[i].masked_value()).into());
        }
        Ok(Some(outputs))
    }
}

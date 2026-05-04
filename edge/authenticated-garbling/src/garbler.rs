//! Garbler in Authenticated Garbling
use crate::preprocesser::f_preprocessing;
use crate::preprocesser::wire::WirePreProcessor;
use crate::ps::PartyGarbler;
use crate::wire::AuthenticatedWireMod2;
use fancy_garbling::circuit::CircuitExecutor;
use fancy_garbling::circuit_analyzer::CircuitAnalyzer;
use fancy_garbling::{Fancy, FancyBinary, WireLabel, WireMod2};

use rand::{CryptoRng, RngCore};
use swanky_authenticated_bits::and_triples::AndTripleGenerator;
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F128b};
use vectoreyes::U8x16;

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;

/// The authenticated garbling's garbler.
pub struct Garbler<RNG> {
    delta: WireMod2,
    zero: WireMod2,
    current_wire_index: usize,
    auth_shares: Vec<AuthShare<PartyGarbler>>,
    auth_shares_index: usize,
    known_triples: Vec<AuthShare<PartyGarbler>>,
    known_triples_index: usize,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Garbler<RNG> {
    /// Create a new garbler.
    pub fn new(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self> {
        let delta = WireMod2::from_repr(
            AndTripleGenerator::<PartyGarbler>::generate_valid_delta(&mut rng),
            2,
        );
        let zero = WireMod2::rand(&mut rng, 2);
        let one = WireMod2::from_repr(zero.to_repr() ^ delta.to_repr(), 2);
        channel.write(&one.to_repr())?;
        Ok(Garbler {
            delta,
            zero,
            current_wire_index: 0,
            auth_shares: Vec::new(),
            auth_shares_index: 0,
            known_triples: Vec::new(),
            known_triples_index: 0,
            rng,
        })
    }

    /// Retrieve the garbler's delta
    fn delta(&mut self) -> WireMod2 {
        self.delta
    }

    /// Return the garbler's delta as U8x16
    fn delta_u8x16(&mut self) -> U8x16 {
        self.delta().to_repr()
    }

    /// The current output index of the garbling computation.
    fn current_wire_index(&mut self) -> usize {
        let current = self.current_wire_index;
        self.current_wire_index += 1;
        current
    }

    fn get_next_auth_share(&mut self) -> AuthShare<PartyGarbler> {
        let share = self.auth_shares[self.auth_shares_index];
        self.auth_shares_index += 1;
        share
    }

    fn get_next_known_triple(&mut self) -> AuthShare<PartyGarbler> {
        let share = self.known_triples[self.known_triples_index];
        self.known_triples_index += 1;
        share
    }

    /// Pre-process the passed circuit
    pub fn preprocess_circuit<
        C: CircuitExecutor<CircuitAnalyzer> + CircuitExecutor<WirePreProcessor<PartyGarbler>>,
    >(
        &mut self,
        circuit: &C,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        let mut and_generator =
            AndTripleGenerator::new_with_delta(self.delta_u8x16(), channel, &mut self.rng)?;
        let (auth_shares, known_triples) =
            f_preprocessing(circuit, &mut and_generator, channel, &mut self.rng)?;
        self.auth_shares = auth_shares;
        self.known_triples = known_triples;
        Ok(())
    }

    /// Encode an authenticated wire representing the zero wire for the [`Garbler`].
    pub fn encode_auth_zero(&mut self) -> swanky_error::Result<AuthenticatedWire> {
        let zero = WireMod2::rand(&mut self.rng, 2);
        let index = self.current_wire_index();

        let gb_auth_zero_wire = AuthenticatedWireMod2::new(zero, self.get_next_auth_share(), index);
        Ok(gb_auth_zero_wire)
    }

    /// Encode many authenticate zero wires for the [`Garbler`].
    pub fn encode_many_auth_zeros(
        &mut self,
        nbits: usize,
    ) -> swanky_error::Result<Vec<AuthenticatedWire>> {
        (0..nbits).map(|_| self.encode_auth_zero()).collect()
    }
    /// Encode the wire label that the [`Garbler`] sends to the Evaluator
    pub fn encode_wire(
        &mut self,
        masked_val: F2,
        zero: WireMod2,
    ) -> swanky_error::Result<WireMod2> {
        let delta = self.delta();
        let ev_wire_label =
            zero + WireMod2::from_repr(U8x16::from(masked_val * F128b::from(delta.to_repr())), 2);
        Ok(ev_wire_label)
    }
    /// The [`Garbler`] encodes several masked values for the Evaluator
    ///
    /// # Panics
    /// Panics if the length of `vals` and `zeroes` are not equal.
    pub fn encode_many_wires(
        &mut self,
        masked_vals: &[F2],
        zeroes: &[WireMod2],
    ) -> swanky_error::Result<Vec<WireMod2>> {
        assert_eq!(masked_vals.len(), zeroes.len());

        masked_vals
            .iter()
            .zip(zeroes.iter())
            .map(|(x, zero)| self.encode_wire(*x, *zero))
            .collect()
    }
}

impl<RNG> FancyBinary for Garbler<RNG>
where
    RNG: RngCore + CryptoRng,
{
    fn and(
        &mut self,
        la0: &Self::Item,
        lb0: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // This index is called γ in the paper
        let index = self.current_wire_index();
        // This is the share for wire label L_{γ,0}
        let lc_share = self.get_next_auth_share();
        // This is the and triple share for wire label L_{γ,0}
        let lc_triple = self.get_next_known_triple();

        // Compute l1 from l0 for both inputs
        //
        // This wire label is L_{α,1} = L_{α,0} + Δ
        let la1 = la0.wire_label() + self.delta();
        // This wire label is L_{β,1} = L_{β,0} + Δ
        let lb1 = lb0.wire_label() + self.delta();

        // Hash l0 and l1 from both inputs and use the current index as a tweak
        //
        // This is H(L_{α,0}, γ) in the paper
        let h_la0 = la0.wire_label().hash(index as u128);
        // This is H(L_{β,0}, γ) in the paper
        let h_lb0 = lb0.wire_label().hash(index as u128);
        // This is H(L_{α,1}, γ) in the paper
        let h_la1 = la1.hash(index as u128);
        // This is H(L_{β,1}, γ) in the paper
        let h_lb1 = lb1.hash(index as u128);

        // Extract the share keys for the inputs, the current gate share, and the and triple
        // This is K[s_α] in the paper
        let key_a = la0.auth_share().key();
        // This is K[s_β] in the paper
        let key_b = lb0.auth_share().key();
        // This is K[s_γ] in the paper
        let key_c = lc_share.key();
        // This is K[s*_γ] in the paper
        let key_c_triple = lc_triple.key();

        // Compute Δ_rα := Δ x r_α: if r_α is 0, then this value is 0, otherwise its Δ
        let delta_bit_a = U8x16::from(la0.auth_share().bit() * F128b::from(self.delta_u8x16()));
        // Compute Δ_rβ := Δ x r_β: if r_β is 0, then this value is 0, otherwise its Δ
        let delta_bit_b = U8x16::from(lb0.auth_share().bit() * F128b::from(self.delta_u8x16()));
        // Compute Δ_rγ := Δ x r_γ: if r_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c = U8x16::from(lc_share.bit() * F128b::from(self.delta_u8x16()));
        // Compute Δ_r*γ := Δ x r*_γ: if r*_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c_triple = U8x16::from(lc_triple.bit() * F128b::from(self.delta_u8x16()));

        // Gate_{γ,0} = H(L_{α,0}, γ) + H(L_{α,1}, γ) + K[s_β] + Δ_rβ
        let gate0 = h_la0 ^ h_la1 ^ key_b ^ delta_bit_b;
        // Gate_{γ,1} = H(L_{β,0}, γ) + H(L_{β,1}, γ) + K[s_α] + Δ_rα + L_{α,0}
        let gate1 = h_lb0 ^ h_lb1 ^ key_a ^ delta_bit_a ^ la0.wire_label().to_repr();
        // L_{γ,0} = H(L_{α,0}, γ) + H(L_{β,0}, γ) + K[s_γ] + Δ_rγ + K[s*_γ] + Δ_r*γ
        let lc0 = h_la0 ^ h_lb0 ^ key_c ^ delta_bit_c ^ key_c_triple ^ delta_bit_c_triple;
        // b_γ = lsb(L_{γ,0})
        let bit_c = F128b::from(lc0).lsb();

        channel.write(&gate0)?;
        channel.write(&gate1)?;
        channel.write(&bit_c)?;

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

        // The Garbler receives the value z'γ from the Evaluator so that
        // they can locally compute their share of c_γ
        let lc_value: F2 = channel.read()?;

        // The Garbler computes its share of the validation bit
        // c_γ :=  (z'α ⊕ λ_α) ∧ (z'β ⊕ λ_β ) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'β λ_α ⊕ z'α λ_β ⊕ λ_α λ_β) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)

        // The Garbler first creates the constant share of (z'α z'β ⊕ z'γ )
        let share_masks: AuthShare<PartyGarbler> = AuthShareGenerator::constant_with_delta(
            la_value * lb_value + lc_value,
            self.delta_u8x16(),
        );
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
            self.delta_u8x16(),
            &mut validation_bit,
            channel,
        )?;

        assert_eq!(
            validation_bit[0],
            F2::ZERO,
            "Garbler's authentication validation check failed at index {index}"
        );

        Ok(AuthenticatedWireMod2::new_with_value(
            lc_value,
            WireMod2::from_repr(lc0, 2),
            lc_share,
            index,
        ))
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2::new_with_value(
            x.masked_value() + y.masked_value(),
            // L_{γ,0} = L_{α,0} + L_{β,0}
            x.wire_label() + y.wire_label(),
            // TODO: This is already computed in preprocessing, maybe re-use it?
            //       although i am not sure if the storage is worth it.
            x.auth_share() ^ y.auth_share(),
            self.current_wire_index(),
        )
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2::new_with_value(
            x.masked_value() + F2::from(1),
            WireMod2::from_repr(x.wire_label().to_repr() ^ self.zero.to_repr(), 2),
            x.auth_share(),
            x.index(),
        )
    }
}

impl<RNG: RngCore + CryptoRng> Fancy for Garbler<RNG> {
    type Item = AuthenticatedWire;

    /// Encodes several bits as authenticated shares.
    ///
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<<Self as Fancy>::Item>> {
        assert_eq!(values.len(), moduli.len());

        // Garbler generates authenticated wires for each of their
        // inputs. The wire label is that of the zero value since that
        // is the only wire label needed for garbling.
        // By generating these authenticated wires, the garbler also creates
        // shares for each of them.
        let mut my_auth_wires = self.encode_many_auth_zeros(values.len())?;

        // The Evaluator opens their share [s_w] to the Garbler
        // Because this is effectively being used to compute the
        // Garblers's input labels, we use the Garbler's
        // authenticated wire shares
        let mut their_bits = Vec::with_capacity(values.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &my_auth_wires
                .iter()
                .map(|auth_wire| auth_wire.auth_share())
                .collect::<Vec<AuthShare<PartyGarbler>>>(),
            self.delta_u8x16(),
            &mut their_bits,
            channel,
        )?;

        let mut my_masked_values = Vec::with_capacity(values.len());
        for (i, b) in their_bits.iter().enumerate() {
            // Garbler computes their masked values x_w + λ_w := x_w ⊕ s_w ⊕ r_w
            my_masked_values.push(b + my_auth_wires[i].auth_share().bit() + F2::from(values[i]));
        }
        // The Garbler uses their masked value and the pre-generated zero wire labels to create
        // their wire labels L_{x_w + λ_w}.
        let my_wire_labels = self.encode_many_wires(
            &my_masked_values,
            &my_auth_wires
                .iter()
                .map(|w| w.wire_label())
                .collect::<Vec<WireMod2>>(),
        )?;

        // The Garbler sends out the labels L_{x_w + λ_w}  and x_w + λ_w to the Evaluator
        for (i, wire) in my_wire_labels.iter().enumerate() {
            channel.write(&wire.to_repr())?;
            channel.write(&my_masked_values[i])?;
        }

        // The Garbler stores their own masked values for later use in the final authentication
        // step before the evaluator can open their values
        for i in 0..my_auth_wires.len() {
            my_auth_wires[i].set_masked_value(my_masked_values[i]);
        }

        Ok(my_auth_wires)
    }

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        // The Garbler generates authenticated wires for the Evaluators values
        // creating authenticated shares for each. This means that the Evaluator's
        // input labels are index first.
        // The wire label is that of the zero value since that
        // is the only wire label needed for garbling.
        let mut their_auth_wires = self.encode_many_auth_zeros(moduli.len())?;

        // The Garbler opens their share [r_w] to the Evaluator
        // Because this is effectively being used to compute the
        // Evaluator's input labels, we use the Evaluator's
        // authenticated wire shares
        AuthShareGenerator::open_my_shares(
            &their_auth_wires
                .iter()
                .map(|auth_wire| auth_wire.auth_share())
                .collect::<Vec<AuthShare<PartyGarbler>>>(),
            channel,
        )?;

        // Garbler receives y_w + λ_w := y_w ⊕ s_w ⊕ r_w from the Evaluator
        let their_masked_values = (0..moduli.len())
            .map(|_| channel.read())
            .collect::<Result<Vec<_>>>()?;

        // The Garbler generates wire labels L_{y_w + λ_w} for each of the Evaluators masked values using
        // the zero wire labels that the Garbler generated in the line above.
        let their_wire_labels = self.encode_many_wires(
            &their_masked_values,
            &their_auth_wires
                .iter()
                .map(|w| w.wire_label())
                .collect::<Vec<WireMod2>>(),
        )?;
        // The Garbler sends out the labels L_{y_w + λ_w}  to the Evaluator
        for w in their_wire_labels {
            channel.write(&w.to_repr())?;
        }

        // The Garbler stores the masked values of the Evaluator to later use them in the final authentication
        // step before the evaluator can open their values.
        for i in 0..their_auth_wires.len() {
            their_auth_wires[i].set_masked_value(their_masked_values[i]);
        }

        Ok(their_auth_wires)
    }

    fn constant(
        &mut self,
        _x: u16,
        _q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<AuthenticatedWire> {
        // We haven't implemented a way to take advantage of constant wires
        // in FancyBinary. So they need to be treated as input wires.
        let index = self.current_wire_index();
        // Constant wires get their own dedicated authenticated share just like
        // an input wire.
        let current_share = self.get_next_auth_share();
        AuthShareGenerator::open_my_shares(&[current_share], channel)?;

        let zero = WireMod2::rand(&mut self.rng, 2);
        // The garbler receives the masked value from the evaluator
        let masked_value = channel.read()?;
        // The garbler sends the wire label associated with the masked value to the evaluator
        let wire_label = zero + self.delta() * u16::from(masked_value);
        channel.write(&wire_label.to_repr())?;

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
        let auth_share: AuthShare<PartyGarbler> = x.auth_share();
        let mut out = Vec::with_capacity(1);
        AuthShareGenerator::open_with_delta(&[auth_share], self.delta_u8x16(), &mut out, channel)?;
        Ok(None)
    }
    // Preferable function when processing multiple outputs!
    // It can efficiently batch opening bits.
    fn outputs(
        &mut self,
        x: &[AuthenticatedWire],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u16>>> {
        let auth_shares: Vec<AuthShare<PartyGarbler>> =
            x.iter().map(|wire| wire.auth_share()).collect();
        let mut outputs = Vec::with_capacity(x.len());
        AuthShareGenerator::open_with_delta(
            &auth_shares,
            self.delta_u8x16(),
            &mut outputs,
            channel,
        )?;
        Ok(None)
    }
}

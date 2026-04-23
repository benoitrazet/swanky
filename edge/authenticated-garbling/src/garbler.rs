//! Garbler in Authenticated Garbling
use crate::mux;
use crate::preprocesser::wire::WirePreProcessor;
use crate::preprocesser::{f_preprocessing, wire::PreProcessedWire};
use crate::ps::PartyGarbler;
use crate::wire::AuthenticatedWireMod2;
use fancy_garbling::circuit::CircuitExecutor;
use fancy_garbling::circuit_analyzer::CircuitAnalyzer;
use fancy_garbling::{Fancy, FancyBinary, WireLabel, WireMod2};

use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use swanky_authenticated_bits::and_triples::AndTripleGenerator;
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_field_binary::{F2, F128b};
use vectoreyes::U8x16;

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<RNG> {
    delta: WireMod2, // delta wire-label.
    zero: WireMod2,  // delta wire-label.
    current_wire_index: usize,
    preprocessed_wires_map: HashMap<usize, PreProcessedWire<PartyGarbler>>,
    known_triples_map: HashMap<usize, PreProcessedWire<PartyGarbler>>,
    their_input_size: usize,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Garbler<RNG> {
    /// Create a new garbler.
    pub fn new(mut rng: RNG, channel: &mut Channel) -> swanky_error::Result<Self> {
        let delta = WireMod2::from_repr(
            AndTripleGenerator::<PartyGarbler>::generate_valid_delta(&mut rng),
            2,
        );
        let zero = WireMod2::rand(&mut rng, 2);
        let one = zero + delta;
        channel.write(&one.to_repr())?;
        Ok(Garbler {
            delta,
            zero,
            current_wire_index: 0,
            preprocessed_wires_map: HashMap::new(),
            known_triples_map: HashMap::new(),
            their_input_size: 0,
            rng,
        })
    }

    /// Retrieve the garbler's delta
    pub fn delta(&mut self) -> WireMod2 {
        self.delta
    }

    /// Return the garbler's delta as U8x16
    pub fn delta_u8x16(&mut self) -> U8x16 {
        self.delta().to_repr()
    }

    /// The current output index of the garbling computation.
    fn current_wire_index(&mut self) -> usize {
        let current = self.current_wire_index;
        self.current_wire_index += 1;
        current
    }
    /// Returns the [`AuthShare`] associated with the current wire
    fn get_current_wire_share(&mut self, index: usize) -> AuthShare<PartyGarbler> {
        self.preprocessed_wires_map[&index].into_auth_share()
    }
    /// Returns the [`AuthShare`] associated with the current wire
    fn get_current_wire_triple(&mut self, index: usize) -> AuthShare<PartyGarbler> {
        self.known_triples_map[&index].into_auth_share()
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
        let (preprocessed_wires_map, known_triples_map) =
            f_preprocessing(circuit, &mut and_generator, channel, &mut self.rng)?;
        self.preprocessed_wires_map = preprocessed_wires_map;
        self.known_triples_map = known_triples_map;
        Ok(())
    }

    /// Encode an authenticated wire representing the zero wire for the [`Garbler`].
    pub fn encode_auth_wire(&mut self) -> swanky_error::Result<AuthenticatedWire> {
        let zero = WireMod2::rand(&mut self.rng, 2);
        let index = self.current_wire_index();

        let gb_auth_zero_wire =
            AuthenticatedWireMod2::new(zero, self.get_current_wire_share(index), index);
        Ok(gb_auth_zero_wire)
    }

    /// Encode many authenticate zero wires for the [`Garbler`].
    pub fn encode_many_auth_wires(
        &mut self,
        nbits: usize,
    ) -> swanky_error::Result<Vec<AuthenticatedWire>> {
        let mut gb_wires = Vec::with_capacity(nbits);
        for _ in 0..nbits {
            let gb_wire = self.encode_auth_wire()?;
            gb_wires.push(gb_wire);
        }
        Ok(gb_wires)
    }
    /// Encode the wire label that the [`Garbler`] sends to the Evaluator
    pub fn encode_wire(
        &mut self,
        masked_val: F2,
        zero: WireMod2,
    ) -> swanky_error::Result<WireMod2> {
        let delta = self.delta();
        let ev_wire_label = zero + delta * u16::from(masked_val);
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
        let mut ev_wires = Vec::with_capacity(masked_vals.len());
        for (x, zero) in masked_vals.iter().zip(zeroes.iter()) {
            let ev_wire_label = self.encode_wire(*x, *zero)?;
            ev_wires.push(ev_wire_label);
        }
        Ok(ev_wires)
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
        let lc0_share = self.get_current_wire_share(index);
        // This is the and triple share for wire label L_{γ,0}
        let lc0_triple = self.get_current_wire_triple(index);

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
        let key_c = lc0_share.key();
        // This is K[s*_γ] in the paper
        let key_c_triple = lc0_triple.key();

        // Compute Δ_rα := Δ x r_α: if r_α is 0, then this value is 0, otherwise its Δ
        let delta_bit_a = mux(la0.auth_share().bit(), 0.into(), self.delta_u8x16());
        // Compute Δ_rβ := Δ x r_β: if r_β is 0, then this value is 0, otherwise its Δ
        let delta_bit_b = mux(lb0.auth_share().bit(), 0.into(), self.delta_u8x16());
        // Compute Δ_rγ := Δ x r_γ: if r_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c = mux(lc0_share.bit(), 0.into(), self.delta_u8x16());
        // Compute Δ_r*γ := Δ x r*_γ: if r*_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c_triple = mux(lc0_triple.bit(), 0.into(), self.delta_u8x16());

        // Gate_{γ,0} = H(L_{α,0}, γ) + H(L_{α,1}, γ) + K[s_β] + Δ_rβ
        let gate0 = h_la0 + h_la1 + key_b + delta_bit_b;
        // Gate_{γ,1} = H(L_{β,0}, γ) + H(L_{β,1}, γ) + K[s_α] + Δ_rα + L_{α,0}
        let gate1 = h_lb0 + h_lb1 + key_a + delta_bit_a + la0.wire_label().to_repr();
        // L_{γ,0} = H(L_{α,0}, γ) + H(L_{β,0}, γ) + K[s_γ] + Δ_rγ + K[s*_γ] + Δ_r*γ
        let lc0 = h_la0 + h_lb0 + key_c + delta_bit_c + key_c_triple + delta_bit_c_triple;
        // b_γ = lsb(L_{γ,0})
        let bit_c = F128b::from(lc0).lsb();

        channel.write(&gate0)?;
        channel.write(&gate1)?;
        channel.write(&bit_c)?;

        let la_value = la0.masked_value();
        let lb_value = lb0.masked_value();

        let lc_value: F2 = channel.read().unwrap();
        let mut my_validation_share = // ⊕ z'α ∧ z'β ∧ s_β 
                        la_value * lc_value * lc0_share.bit()
                        // ⊕ z'β ∧ z'γ ∧ s_α
                        + lb_value * lc_value * lc0_share.bit()
                        // ⊕ z'γ ∧ s*_γ
                        + lc_value * lc0_triple.bit()
                        // ⊕ z'α ∧ z'β ∧ s_γ
                        + la_value * lb_value * lc0_share.bit()
                        // ⊕ z'α ∧ s_β ∧ s_γ
                        + la_value * lb0.bit() * lc0_share.bit()
                        // ⊕ z'β ∧ s_α ∧ s_γ
                        + lb_value * la0.bit()* lc0_share.bit()
                        // s*_γ ∧ s_γ
                        + lc0_triple.bit() * lc0_share.bit();

        // The garbler receives the evaluator's part of the validation bit
        let their_validation_share: F2 = channel.read().unwrap();
        // The evaluator sends their part of the validation bit
        channel.write(&my_validation_share)?;
        // The garbler adds the last part of the validation bit z'α ∧ z'β ∧ z'γ
        my_validation_share += their_validation_share + la_value * lb_value * lc_value;

        // The garbler aborts if the validation is bit is not equal to 0
        assert_eq!(
            my_validation_share,
            0.into(),
            "Garbler's authentication validation check failed at index {index}"
        );
        Ok(AuthenticatedWireMod2::new_with_value(
            lc_value,
            WireMod2::from_repr(lc0, 2),
            lc0_share,
            index,
        ))
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let index = self.current_wire_index();
        AuthenticatedWireMod2::new_with_value(
            x.masked_value() + y.masked_value(),
            // L_{γ,0} = L_{α,0} + L_{β,0}
            x.wire_label() + y.wire_label(),
            // TODO: This is already computed in preprocessing, maybe re-use it?
            //       although i am not sure if the storage is worth it.
            x.auth_share() ^ y.auth_share(),
            index,
        )
    }

    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2::new_with_value(
            x.masked_value() + F2::from(1),
            x.wire_label() + self.zero,
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
        _moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<<Self as Fancy>::Item>> {
        // The Garbler generates authenticated wires for the Evaluators values
        // creating authenticated shares for each. This means that the Evaluator's
        // input labels are index first.
        // The wire label is that of the zero value since that
        // is the only wire label needed for garbling.
        let mut their_auth_wires: Vec<AuthenticatedWireMod2<PartyGarbler>> =
            self.encode_many_auth_wires(self.their_input_size)?;

        // Garbler generates authenticated wires for each of their
        // inputs. The wire label is that of the zero value since that
        // is the only wire label needed for garbling.
        // By generating these authenticated wires, the garbler also creates
        // shares for each of them.
        let mut my_auth_wires: Vec<AuthenticatedWireMod2<PartyGarbler>> =
            self.encode_many_auth_wires(values.len())?;

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
        let mut their_masked_values: Vec<F2> = Vec::with_capacity(self.their_input_size);
        let _ = values
            .iter()
            .map(|_| their_masked_values.push(channel.read().unwrap()));

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
        let _ = their_wire_labels
            .iter()
            .map(|w| channel.write(&w.to_repr()));

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

        let mut my_masked_values: Vec<F2> = Vec::with_capacity(values.len());
        for (i, b) in their_bits.iter().enumerate() {
            // Garbler computes their masked values x_w + λ_w := x_w ⊕ s_w ⊕ r_w
            my_masked_values[i] = b + my_auth_wires[i].auth_share().bit() + F2::from(values[i]);
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
            let _ = channel.write(&wire.to_repr());
            let _ = channel.write(&my_masked_values[i]);
        }

        // The Garbler stores the masked values of the Evaluator to later use them in the final authentication
        // step before the evaluator can open their values.
        for i in 0..their_auth_wires.len() {
            their_auth_wires[i].set_masked_value(their_masked_values[i]);
        }

        // The Garbler stores their own masked values for later use in the final authentication
        // step before the evaluator can open their values
        for i in 0..my_auth_wires.len() {
            my_auth_wires[i].set_masked_value(my_masked_values[i]);
        }

        // The Garbler concatenated both inputs stating with the evaluator's and returns the results.
        their_auth_wires.extend(my_auth_wires);
        Ok(their_auth_wires)
    }

    fn receive_many(
        &mut self,
        _moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Garbler cannot receive wire labels from the Evaluator")
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
        let current_share = self.get_current_wire_share(index);
        AuthShareGenerator::open_my_shares(&[current_share], channel)?;

        let zero = WireMod2::rand(&mut self.rng, 2);
        // The garbler receives the masked value from the evaluator
        let masked_value = channel.read().unwrap();
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
        Ok(Some(u16::from(out[0])))
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
        Ok(Some(outputs.iter().map(|o| u16::from(*o)).collect()))
    }
}

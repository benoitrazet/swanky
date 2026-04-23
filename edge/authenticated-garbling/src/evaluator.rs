//! Evaluator for Authenticated Garbling

use std::collections::HashMap;

use fancy_garbling::{BinaryBundle, Fancy, FancyBinary, WireLabel, WireMod2};
use rand::{CryptoRng, RngCore};
use swanky_authenticated_bits::{
    and_triples::AndTripleGenerator,
    authshares::{AuthShare, AuthShareGenerator},
};
use swanky_channel::Channel;

use swanky_field_binary::{F2, F128b};
use vectoreyes::U8x16;

use crate::{
    mux,
    preprocesser::{f_preprocessing, wire::PreProcessedWire},
    ps::PartyEvaluator,
    unifier::{CircuitExecutor, CircuitExecutorItem},
    wire::AuthenticatedWireMod2,
};

type AuthenticatedWire = AuthenticatedWireMod2<PartyEvaluator>;
/// The authenticated garbling's evaluator
pub struct Evaluator<RNG> {
    one: WireMod2,
    authentication_delta: U8x16,
    current_wire_index: usize,
    preprocessed_wires_map: HashMap<usize, PreProcessedWire<PartyEvaluator>>,
    known_triples_map: HashMap<usize, PreProcessedWire<PartyEvaluator>>,
    their_input_size: usize,
    // TODO: Get ride of this once when refactor the
    // encode/receive methods of the ev/gb
    values: Vec<F2>,
    pub(crate) rng: RNG,
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
            preprocessed_wires_map: HashMap::new(),
            known_triples_map: HashMap::new(),
            current_wire_index: 0,
            their_input_size: 0,
            // TODO: Get ride of this once when refactor the
            // encode/receive methods of the ev/gb
            values: Vec::new(),
            rng,
        })
    }

    /// Pre-process the passed circuit
    pub fn preprocess_circuit(
        &mut self,
        circuit: &impl Fn(
            &mut CircuitExecutor<PartyEvaluator, RNG>,
            BinaryBundle<CircuitExecutorItem<PartyEvaluator>>,
            BinaryBundle<CircuitExecutorItem<PartyEvaluator>>,
            &mut Channel,
        )
            -> swanky_error::Result<BinaryBundle<CircuitExecutorItem<PartyEvaluator>>>,
        my_input_size: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        // The garbler and evaluator exchange their input sizes
        let _ = channel.write(&my_input_size);
        self.their_input_size = channel.read().unwrap();

        let mut and_generator =
            AndTripleGenerator::new_with_delta(self.delta(), channel, &mut self.rng)?;
        let (preprocessed_wires_map, known_triples_map) = f_preprocessing(
            &circuit,
            &mut and_generator,
            my_input_size + self.their_input_size,
            channel,
            &mut self.rng,
        )?;
        self.preprocessed_wires_map = preprocessed_wires_map;
        self.known_triples_map = known_triples_map;
        self.authentication_delta = and_generator.delta();
        Ok(())
    }
    /// Set the input values of the Evaluator
    ///
    /// TODO: Get ride of this once when refactor the
    /// encode/receive methods of the ev/gb
    pub fn set_values(&mut self, values: Vec<F2>) {
        self.values = values;
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
    /// Returns the [`AuthShare`] associated with the current wire
    fn get_current_wire_share(&mut self, index: usize) -> AuthShare<PartyEvaluator> {
        self.preprocessed_wires_map[&index].into_auth_share()
    }
    /// Returns the [`AuthShare`] associated with the current wire
    fn get_current_wire_triple(&mut self, index: usize) -> AuthShare<PartyEvaluator> {
        self.known_triples_map[&index].into_auth_share()
    }
}

impl<RNG: CryptoRng + RngCore> FancyBinary for Evaluator<RNG> {
    /// Overriding `negate` to be a noop: entirely handled on garbler's end.
    /// This is also why the index of the input and output wires of this
    /// gate are the same.
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2::new(x.wire_label() + self.one, x.auth_share(), x.index())
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
        let lc_share = self.get_current_wire_share(index);
        // This is the current wire's authenticated triple
        let lc_triple = self.get_current_wire_triple(index);

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
        let gate0 = gate_c0 + lb.auth_share().mac();
        // This is the value: Gate_1 = Gate_{γ,1} + M[s_α]
        let gate1 = gate_c1 + la.auth_share().mac();

        // This is the value H(L_{α, z_α + λ_α}, γ)
        let h_la = la.wire_label().hash(index as u128);
        // This is the value H(L_{β, z_β + λ_β}, γ)
        let h_lb = lb.wire_label().hash(index as u128);

        // z'α := z_α + λ_α, where z_α is the actual wire value of the input
        // wire with label L_α and λ_α is the mask of that value
        let la_value = la.masked_value();
        // z'γ := z_β + λ_β, where z_β is the actual wire value of the input
        // wire with label L_β and λ_β is the mask of that value
        let lb_value = lb.masked_value();

        // This is the value (z_α + λ_α)Gate_0
        let gate0_muxed = mux(la_value, 0.into(), gate0);
        // This is the value (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let gate1_muxed = mux(lb_value, 0.into(), gate1 + la.wire_label().to_repr());

        // This the value:
        //  L_{γ, z_γ + λ_γ} := H(L_{α, z_α + λ_α}, γ) + H(L_{β, z_β + λ_β}, γ) + M[s_γ]
        //                      + M[s*_γ] + (z_α + λ_α)Gate_0 + (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let lc_label = h_la + h_lb + mac_share + mac_triple + gate0_muxed + gate1_muxed;

        // The current masked value of the wire is:
        // z'γ := z_γ + λ_γ := b_γ + lsb(L_{γ, z_γ + λ_γ})
        let lc_value = F128b::from(lc_label).lsb() + bit_c;
        let mut lc = AuthenticatedWireMod2::new_with_value(
            lc_value,
            WireMod2::from_repr(lc_label, 2),
            lc_share,
            index,
        );
        // The Evaluator computes its share of the validation bit
        // c_γ :=  (z'α ⊕ λ_α) ∧ (z'β ⊕ λ_β ) ∧ (z'γ ⊕ λ_γ )
        // If we expand this we get:
        //  z'α ∧ z'β ∧ z'γ (which can be added when c_γ is opened so that the parties don't add it twice)
        let mut my_validation_share = // ⊕ z'α ∧ z'β ∧ s_β 
                        la_value * lc_value * lb.bit()
                        // ⊕ z'β ∧ z'γ ∧ s_α
                        + lb_value * lc_value * la.bit()
                        // ⊕ z'γ ∧ s*_γ
                        + lc_value * lc_triple.bit()
                        // ⊕ z'α ∧ z'β ∧ s_γ
                        + la_value * lb_value * lc.bit()
                        // ⊕ z'α ∧ s_β ∧ s_γ
                        + la_value * lb.bit() * lc.bit()
                        // ⊕ z'β ∧ s_α ∧ s_γ
                        + lb_value * la.bit()* lc.bit()
                        // s*_γ ∧ s_γ
                        + lc_triple.bit() * lc.bit();

        // The evaluator sends out the masked bit z'γ 
        channel.write(&lc_value)?;
        // The evaluator sends their part of the validation bit
        channel.write(&my_validation_share)?;
        // The evaluator receives the garbler's part of the validation bit
        let their_validation_share: F2 = channel.read().unwrap();
        // The evaluator adds the last part of the validation bit z'α ∧ z'β ∧ z'γ
        my_validation_share += their_validation_share + la_value * lb_value * lc_value;

        // The evaluator aborts if the validation is bit is not equal to 0
        assert_eq!(
            my_validation_share,
            0.into(),
            "Evaluator's authentication validation check failed at index {index}"
        );
        Ok(lc)
    }
}

impl<RNG: CryptoRng + RngCore> Fancy for Evaluator<RNG> {
    type Item = AuthenticatedWire;

    fn encode_many(
        &mut self,
        _values: &[u16],
        _moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Evaluator cannot encode wire labels");
    }

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        // The Evaluator retrieves authenticated shares for their own inputs first.
        // This means that we are assuming that those inputs will be indexed first.
        let my_auth_shares: Vec<AuthShare<PartyEvaluator>> = (0..moduli.len())
            .map(|_i| {
                let index = self.current_wire_index();
                self.get_current_wire_share(index)
            })
            .collect();
        // The Evaluator retrieves authenticated shares for the garbler's inputs.
        let their_auth_shares: Vec<AuthShare<PartyEvaluator>> = (0..self.their_input_size)
            .map(|_i| {
                let index = self.current_wire_index();
                self.get_current_wire_share(index)
            })
            .collect();

        let mut their_bits = Vec::with_capacity(self.their_input_size);

        // The Evaluator opens and receives the garblers share [r_w].
        // Because this is effectively being used to compute the
        // Evaluator's input labels, we use the Evaluator's
        // authenticated shares
        AuthShareGenerator::open_their_shares_with_delta(
            &my_auth_shares,
            self.delta(),
            &mut their_bits,
            channel,
        )?;

        // TODO: Change how the evaluator retrieves their values and possibly
        // move this part all together when we refactor EV/GB
        let mut my_masked_values: Vec<F2> = Vec::with_capacity(self.values.len());
        for (i, b) in their_bits.iter().enumerate() {
            // Evaluator computes their masked values y_w + λ_w := y_w ⊕ s_w ⊕ r_w
            my_masked_values[i] = b + my_auth_shares[i].bit() + F2::from(self.values[i]);
            // Evaluator sends y_w + λ_w  to the Garbler
            let _ = channel.write(&my_masked_values[i]);
        }

        let mut my_auth_wires: Vec<AuthenticatedWire> = Vec::with_capacity(self.values.len());
        for (i, masked_value) in my_masked_values.iter().enumerate() {
            // The Evaluator retrieves the wire labels for their own input
            let wire_label = WireMod2::from_repr(channel.read().unwrap(), 2);
            // The Evaluator constructs authenticated values for all their input wires
            my_auth_wires.push(AuthenticatedWireMod2::new_with_value(
                *masked_value,
                wire_label,
                my_auth_shares[i],
                i,
            ));
        }

        AuthShareGenerator::open_my_shares(&their_auth_shares, channel)?;

        let mut their_auth_wires: Vec<AuthenticatedWire> = Vec::with_capacity(self.values.len());
        // We need to offset the authenticated wire indices of the garbler because they come second
        let index_offset = self.values.len();

        // The Evaluator receives the wire labels and masked values of the Garbler and uses these values
        // to construct the garbler's authenticated wires
        for (i, share) in their_auth_shares.iter().enumerate() {
            let their_wire_label = WireMod2::from_repr(channel.read().unwrap(), 2);
            let their_masked_value: F2 = channel.read().unwrap();
            their_auth_wires.push(AuthenticatedWireMod2::new_with_value(
                their_masked_value,
                their_wire_label,
                *share,
                i + index_offset,
            ));
        }
        // The Evaluator concatenates both inputs stating with the evaluator's and returns the results.
        my_auth_wires.extend(their_auth_wires.into_iter());
        Ok(my_auth_wires)
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
        let current_share = self.get_current_wire_share(index);

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

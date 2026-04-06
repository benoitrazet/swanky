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
    values: HashMap<usize, F2>,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Evaluator<RNG> {
    /// Create a new `Evaluator`.
    pub fn new(channel: &mut Channel, rng: RNG) -> swanky_error::Result<Self> {
        // Receive the constant one wirelabel from the garbler. This is used to
        // make negation free.
        let one = channel.read::<U8x16>()?;
        Ok(Evaluator {
            one: WireMod2::from_repr(one, 2),
            authentication_delta: U8x16::from(0),
            preprocessed_wires_map: HashMap::new(),
            known_triples_map: HashMap::new(),
            values: HashMap::new(),
            current_wire_index: 0,
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
        input_size: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        let mut and_generator = AndTripleGenerator::new(channel, &mut self.rng)?;
        let (preprocessed_wires_map, known_triples_map) = f_preprocessing(
            &circuit,
            &mut and_generator,
            input_size,
            channel,
            &mut self.rng,
        )?;
        self.preprocessed_wires_map = preprocessed_wires_map;
        self.known_triples_map = known_triples_map;
        self.authentication_delta = and_generator.delta();
        Ok(())
    }

    /// Get the deltas, consuming the Evaluator
    pub fn get_delta(&self) -> U8x16 {
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
    /// Returns the underlying value associated with the wire index
    fn get_value(&mut self, index: usize) -> F2 {
        self.values[&index]
    }
    /// Sets the underlying associated with the wire index
    fn insert_value(&mut self, index: usize, value: F2) {
        self.values.insert(index, value);
    }
    /// Read a Wire from the reader.
    pub fn read_wire(
        &mut self,
        _modulus: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<WireMod2> {
        let bytes = channel.read()?;
        Ok(WireMod2::from_repr(bytes, 2))
    }
}


impl<RNG: CryptoRng + RngCore> FancyBinary for Evaluator<RNG> {
    /// Overriding `negate` to be a noop: entirely handled on garbler's end
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2 {
            wire_label: x.wire_label() + self.one,
            auth_share: x.auth_share(),
            index: x.index(),
        }
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let index = self.current_wire_index();
        let current_value = self.get_value(x.index()) + self.get_value(y.index());
        self.insert_value(index, current_value);
        AuthenticatedWireMod2 {
            wire_label: x.wire_label() + y.wire_label(),
            auth_share: x.auth_share() ^ y.auth_share(),
            index,
        }
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

        // z_α + λ_α, where z_α is the actual wire value of the input
        // wire with label L_α and λ_α is the mask of that value
        let la_value = self.get_value(la.index());
        // z_β + λ_β, where z_β is the actual wire value of the input
        // wire with label L_β and λ_β is the mask of that value
        let lb_value = self.get_value(lb.index());

        // This is the value (z_α + λ_α)Gate_0
        let gate0_muxed = mux(la_value, 0.into(), gate0);
        // This is the value (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let gate1_muxed = mux(lb_value, 0.into(), gate1 + la.wire_label().to_repr());

        // This the value:
        //  L_{γ, z_γ + λ_γ} := H(L_{α, z_α + λ_α}, γ) + H(L_{β, z_β + λ_β}, γ) + M[s_γ]
        //                      + M[s*_γ] + (z_α + λ_α)Gate_0 + (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let lc = h_la + h_lb + mac_share + mac_triple + gate0_muxed + gate1_muxed;

        // The current masked value of the wire is:
        // z_γ + λ_γ := b_γ + lsb(L_{γ, z_γ + λ_γ})
        let current_value = F128b::from(lc).lsb() + bit_c;
        self.insert_value(index, current_value);
        Ok(AuthenticatedWireMod2 {
            wire_label: WireMod2::from_repr(lc, 2),
            auth_share: lc_share,
            index,
        })
    }
}

impl<RNG: CryptoRng + RngCore> Fancy for Evaluator<RNG> {
    type Item = AuthenticatedWire;

    fn encode_many(
        &mut self,
        _values: &[u16],
        _moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Evaluator cannot encode values")
    }

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        (0..moduli.len())
            .map(|_| {
                let received_value = channel.read()?;
                let index = self.current_wire_index();
                let wire = AuthenticatedWireMod2 {
                    wire_label: WireMod2::from_repr(received_value, 2),
                    auth_share: self.get_current_wire_share(index),
                    index,
                };
                Ok(wire)
            })
            .collect()
    }
    fn constant(
        &mut self,
        _: u16,
        q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<AuthenticatedWire> {
        let index = self.current_wire_index();
        let wire_label = self.read_wire(q, channel)?;

        Ok(AuthenticatedWireMod2 {
            wire_label,
            auth_share: self.get_current_wire_share(index),
            index,
        })
    }

    fn output(
        &mut self,
        x: &AuthenticatedWire,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        let auth_share: AuthShare<PartyEvaluator> = x.auth_share();
        let mut out = Vec::with_capacity(1);
        AuthShareGenerator::open_with_delta(&[auth_share], self.get_delta(), &mut out, channel)?;
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
        let mut outputs = Vec::with_capacity(x.len());
        AuthShareGenerator::open_with_delta(&auth_shares, self.get_delta(), &mut outputs, channel)?;
        Ok(Some(outputs.iter().map(|o| u16::from(*o)).collect()))
    }
}

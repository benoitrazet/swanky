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
    pub(crate) values: Vec<F2>,
    pub(crate) rng: RNG,
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
            values: Vec::new(),
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
        let (preprocessed_wires_map, known_triples_map, nwires) = f_preprocessing(
            &circuit,
            &mut and_generator,
            input_size,
            channel,
            &mut self.rng,
        )?;
        self.preprocessed_wires_map = preprocessed_wires_map;
        self.known_triples_map = known_triples_map;
        self.authentication_delta = and_generator.delta();
        self.values = Vec::with_capacity(nwires);
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
        self.values[index]
    }
    /// Sets the underlying associated with the wire index
    pub(crate) fn insert_value(&mut self, index: usize, value: F2) {
        self.values[index] = value;
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
    /// Overriding `negate` to be a noop: entirely handled on garbler's end.
    /// This is also why the index of the input and output wires of this
    /// gate are the same.
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2::new(x.wire_label() + self.one, x.auth_share(), x.index())
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let index = self.current_wire_index();
        let current_value = self.get_value(x.index()) + self.get_value(y.index());
        self.insert_value(index, current_value);
        AuthenticatedWireMod2::new(
            x.wire_label() + y.wire_label(),
            x.auth_share() ^ y.auth_share(),
            index,
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
        Ok(AuthenticatedWireMod2::new(
            WireMod2::from_repr(lc, 2),
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
        _moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        // There is an assumption being made here that the garbler and evaluator have the same number
        // of input wires. Since the evaluator inputs come after the garbler's, we need to shift their
        // indices !
        let index_shift = values.len();

        Ok((0..values.len())
            .map(|i| {
                // First we mask the values, remember that we had stored the masks in "self.values"
                // when the evaluator received the garbler's input labels.
                // This value is the following in the paper:
                // y_w + λ_w := y_w ⊕ s_w ⊕ r_w
                let value_f2 = F2::from(values[i]) + self.values[index_shift + i];
                // The evaluator sends that value to the garbler
                channel.write(&value_f2);
                // The evaluator receives the wire label associated with their masked value.
                // This value is the following in the paper:
                // L_{w,y_w ⊕λ_w}
                let wire_label = channel.read().unwrap();
                AuthenticatedWireMod2::new_without_share(
                    WireMod2::from_repr(wire_label, 2),
                    index_shift + i,
                )
            })
            .collect())
    }

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        // Evaluator starts by getting authenticated shares for the Garbler's
        // inputs.
        let mut auth_wires = Vec::with_capacity(moduli.len());
        for _ in 0..moduli.len() {
            let index = self.current_wire_index();
            auth_wires.push(AuthenticatedWireMod2::new(
                WireMod2::from_repr(0.into(), 2),
                self.get_current_wire_share(index),
                index,
            ));
        }
        // Both parties open their input shares to each reach the bit mask that they will use
        // to hide their inputs.
        // The masks are called λ_w in the paper
        let mut masks = Vec::with_capacity(moduli.len());
        AuthShareGenerator::open_with_delta(
            &auth_wires
                .iter()
                .map(|auth_wire| auth_wire.auth_share())
                .collect::<Vec<AuthShare<PartyEvaluator>>>(),
            self.get_delta(),
            &mut masks,
            channel,
        )?;

        (0..moduli.len())
            .map(|i| {
                // The evaluator increments the counter for its own inputs
                let index = self.current_wire_index();
                // The evaluator stores the masks that they will later use
                // to mask their inputs. There is an assumption being made
                // here that the garbler and evaluator have the same number
                // of input wires.
                self.insert_value(index, masks[i]);

                // The evaluator receives the garbler's masked inputs.
                // The values are called the following in the paper:
                // L_{w,x_w ⊕ λ_w}
                let received_value = channel.read()?;
                // We are making an assumption here that the garbler's inputs
                // will be the very first thing to be given an index in the circuit.
                // This is why the index of this wire is i.
                // Moreover, the input wires on the evaluator side do not need an authenticated
                // share: The evaluator only uses share when opening the input wire bit masks
                //        (which we already did), and for each output gate wire.
                let wire = AuthenticatedWireMod2::new_without_share(
                    WireMod2::from_repr(received_value, 2),
                    i,
                );
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

        Ok(AuthenticatedWireMod2::new(
            wire_label,
            self.get_current_wire_share(index),
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

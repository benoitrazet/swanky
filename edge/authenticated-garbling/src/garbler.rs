//! Garbler in Authenticated Garbling
use crate::preprocesser::unifier::{CircuitExecutor, CircuitExecutorItem};
use crate::preprocesser::{f_preprocessing, wire::PreProcessedWire};
use crate::ps::PartyGarbler;
use crate::wire::AuthenticatedWireMod2;
use fancy_garbling::{
    BinaryBundle, Fancy, FancyBinary,WireLabel, WireMod2, util::u128_to_bits,
};

use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use swanky_authenticated_bits::and_triples::AndTripleGenerator;
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_field_binary::F2;

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<RNG> {
    deltas: HashMap<u16, WireMod2>, // map from modulus to associated delta wire-label.
    current_wire_index: usize,
    preprocessed_wires_map: HashMap<usize, PreProcessedWire<PartyGarbler>>,
    known_triples_map: HashMap<usize, PreProcessedWire<PartyGarbler>>,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Garbler<RNG> {
    /// Create a new garbler.
    pub fn new(rng: RNG, channel: &mut Channel) -> swanky_error::Result<Self> {
        Ok(Garbler {
            deltas: HashMap::new(),
            preprocessed_wires_map: HashMap::new(),
            known_triples_map: HashMap::new(),
            current_wire_index: 0,
            rng,
        })
    }

    /// Create a delta if it has not been created yet for this modulus, otherwise just
    /// return the existing one.
    pub fn delta(&mut self, q: u16) -> WireMod2 {
        if let Some(delta) = self.deltas.get(&q) {
            return delta.clone();
        }
        let w = WireMod2::rand_delta(&mut self.rng, q);
        self.deltas.insert(q, w.clone());
        w
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
    /// Pre-process the passed circuit
    pub fn preprocess_circuit(
        &mut self,
        circuit: &impl Fn(
            &mut CircuitExecutor<PartyGarbler>,
            BinaryBundle<CircuitExecutorItem<PartyGarbler>>,
            BinaryBundle<CircuitExecutorItem<PartyGarbler>>,
            &mut Channel,
        )
            -> swanky_error::Result<BinaryBundle<CircuitExecutorItem<PartyGarbler>>>,
        input_size: usize,
        channel: &mut Channel,
        mut rng: &mut RNG,
    ) -> swanky_error::Result<()> {
        let mut and_generator = AndTripleGenerator::new(channel, &mut self.rng)?;
        let (preprocessed_wires_map, known_triples_map) =
            f_preprocessing(&circuit, &mut and_generator, input_size, channel, rng)?;
        self.preprocessed_wires_map = preprocessed_wires_map;
        self.known_triples_map = known_triples_map;
        self.deltas.extend(HashMap::from([(
            2,
            WireLabel::from_repr(and_generator.delta(), 2),
        )]));
        Ok(())
    }

    /// Get the deltas, consuming the Garbler.
    ///
    /// This is useful for reusing wires in multiple garbled circuit instances.
    pub fn get_deltas(self) -> HashMap<u16, WireMod2> {
        self.deltas
    }

    /// Encode an authenticated wire, producing the zero label.
    pub fn encode_auth_wire(&mut self) -> swanky_error::Result<(AuthenticatedWire, WireMod2)> {
        let zero = WireMod2::rand(&mut self.rng, 2);
        let index = self.current_wire_index();

        let wire = AuthenticatedWireMod2 {
            wire_label: zero,
            auth_share: self.get_current_wire_share(index),
            index,
        };
        Ok((wire, zero))
    }

    /// Encode many authenticate wires, producing those wires and their associated zero label.
    pub fn encode_many_auth_wires(
        &mut self,
        nbits: usize,
    ) -> swanky_error::Result<(Vec<AuthenticatedWire>, Vec<WireMod2>)> {
        let mut gbs = Vec::with_capacity(nbits);
        let mut evs = Vec::with_capacity(nbits);
        for _i in 0..nbits {
            let (gb, ev) = self.encode_auth_wire()?;
            gbs.push(gb);
            evs.push(ev);
        }
        Ok((gbs, evs))
    }
    /// Encode a wire label.
    pub fn encode_wire(
        &mut self,
        masked_val: F2,
        zero: WireMod2,
    ) -> swanky_error::Result<WireMod2> {
        let delta = self.delta(2);
        let enc = zero.clone() + delta * u16::from(masked_val);
        Ok(enc)
    }
    /// Encode many wire labels based on the masked values
    ///
    /// # Panics
    /// Panics if the length of `vals` and `zeroes` are not equal.
    pub fn encode_many_wires(
        &mut self,
        masked_vals: &[F2],
        zeroes: &[WireMod2],
    ) -> swanky_error::Result<Vec<WireMod2>> {
        assert_eq!(masked_vals.len(), zeroes.len());
        let mut evs = Vec::with_capacity(masked_vals.len());
        for (x, zero) in masked_vals.iter().zip(zeroes.iter()) {
            let ev = self.encode_wire(*x, *zero)?;
            evs.push(ev);
        }
        Ok(evs)
    }
    /// Encodes several bits as Binary bundles of authenticated shares along with their associated wire masked labels.
    ///
    /// This is done in four steps: First the garbler generates authenticated wires for each of those
    /// inputs and returns the zeroes generated for those wires; Then the garbler open the authenticated
    /// shares associated with each authenticated wire; Then the garbler uses the opened bits to mask their
    /// input values and finally encodes them as labels.
    pub fn bin_encode_wire(
        &mut self,
        val: u128,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<(
        BinaryBundle<AuthenticatedWireMod2<PartyGarbler>>,
        BinaryBundle<WireMod2>,
    )> {
        let xs = u128_to_bits(val, nbits);
        let values: Vec<F2> = xs.iter().map(|b| F2::from(*b)).collect();
        // Garbler generates authenticated wires for each of those
        // inputs and returns the zeroes generated for those wires
        let (gbs, zeroes) = self.encode_many_auth_wires(values.len())?;

        // Garbler open the authenticated shares associated with each authenticated wire
        let mut auth_bits = Vec::with_capacity(values.len());
        AuthShareGenerator::open_with_delta(
            &gbs.iter()
                .map(|auth_wire| auth_wire.auth_share())
                .collect::<Vec<AuthShare<PartyGarbler>>>(),
            self.delta(2).to_repr(),
            &mut auth_bits,
            channel,
        )?;
        // Garbler uses the opened bits to mask their input values
        let masked_values: Vec<F2> = values
            .iter()
            .zip(auth_bits.iter())
            .map(|(val, bit)| val + bit)
            .collect();
        // Garbler encodes the masked values and sends them to the evaluator
        let evs = self.encode_many_wires(&masked_values, &zeroes)?;
        Ok((BinaryBundle::new(gbs), BinaryBundle::new(evs)))
    }
}

impl<RNG> FancyBinary for Garbler<RNG>
where
    RNG: RngCore + CryptoRng,
{
    fn and(
        &mut self,
        A: &Self::Item,
        B: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        todo!()
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        todo!()
    }

    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        todo!()
    }
}

impl<RNG: RngCore + CryptoRng> Fancy for Garbler<RNG> {
    type Item = AuthenticatedWire;

    /// Encodes several bits as authenticated shares.
    ///
    /// This is done in four steps: First the garbler generates authenticated wires for each of those
    /// inputs and returns the zeroes generated for those wires; Then the garbler open the authenticated
    /// shares associated with each authenticated wire; Then the garbler uses the opened bits to mask their
    /// input values, encodes them as labels and finally sends the wire labels associated with those masked values.
    fn encode_many(
        &mut self,
        values: &[u16],
        _moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<<Self as Fancy>::Item>> {
        let values_f2: Vec<F2> = values.iter().map(|v| F2::from(*v)).collect();
        // Garbler generates authenticated wires for each of those
        // inputs and returns the zeroes generated for those wires
        let (auth_wires, zeroes): (Vec<AuthenticatedWireMod2<PartyGarbler>>, Vec<WireMod2>) =
            self.encode_many_auth_wires(values.len())?;

        // Garbler open the authenticated shares associated with each authenticated wire
        let mut auth_bits = Vec::with_capacity(values.len());
        AuthShareGenerator::open_with_delta(
            &auth_wires
                .iter()
                .map(|auth_wire| auth_wire.auth_share())
                .collect::<Vec<AuthShare<PartyGarbler>>>(),
            self.delta(2).to_repr(),
            &mut auth_bits,
            channel,
        )?;
        // Garbler uses the opened bits to mask their input values
        let masked_values: Vec<F2> = values_f2
            .iter()
            .zip(auth_bits.iter())
            .map(|(val, bit)| val + bit)
            .collect();
        // Garbler encodes the masked values and sends them to the evaluator
        let encoded = self.encode_many_wires(&masked_values, &zeroes)?;
        for wire in encoded.iter() {
            channel.write(&wire.to_repr())?;
        }
        Ok(auth_wires)
    }

    fn receive_many(
        &mut self,
        _moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Garbler cannot receive values")
    }
    fn constant(&mut self, x: u16, q: u16, channel: &mut Channel) -> swanky_error::Result<AuthenticatedWire> {
        todo!()
    }

    fn output(&mut self, X: &AuthenticatedWire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        todo!()
    }
}

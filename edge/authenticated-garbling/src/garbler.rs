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
use swanky_channel::Channel;

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<RNG> {
    deltas: HashMap<u16, WireMod2>, // map from modulus to associated delta wire-label.
    current_wire_index: usize,
    preprocessed_wires_map: HashMap<usize, PreProcessedWire<PartyGarbler>>,
    known_triples_map: HashMap<usize, PreProcessedWire<PartyGarbler>>,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore + Clone> Garbler<RNG> {
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

    /// Send a wire over the established channel.
    pub fn send_wire(&mut self, wire: &AuthenticatedWire, channel: &mut Channel) -> swanky_error::Result<()> {
        channel.write(&wire.wire_label().to_repr())?;
        Ok(())
    }

    /// Encode a wire, producing the zero wire as well as the encoded value.
    pub fn encode_wire(
        &mut self,
        val: u16,
        modulus: u16,
    ) -> (AuthenticatedWire, AuthenticatedWire) {
        todo!()
    }

    /// Encode many wires, producing zero wires as well as encoded values.
    ///
    /// # Panics
    /// Panics if the length of `vals` and `moduli` are not equal.
    pub fn encode_many_wires(
        &mut self,
        vals: &[u16],
        moduli: &[u16],
    ) -> swanky_error::Result<(Vec<AuthenticatedWire>, Vec<AuthenticatedWire>)> {
        assert_eq!(vals.len(), moduli.len());

        let mut gbs = Vec::with_capacity(vals.len());
        let mut evs = Vec::with_capacity(vals.len());
        for (x, q) in vals.iter().zip(moduli.iter()) {
            let (gb, ev) = self.encode_wire(*x, *q);
            gbs.push(gb);
            evs.push(ev);
        }
        Ok((gbs, evs))
    }

    /// Encode a `BinaryBundle`, producing zero wires as well as encoded values.
    pub fn bin_encode_wire(
        &mut self,
        val: u128,
        nbits: usize,
    ) -> swanky_error::Result<(BinaryBundle<AuthenticatedWire>, BinaryBundle<AuthenticatedWire>)> {
        let xs = u128_to_bits(val, nbits);
        let ms = vec![2; nbits];
        let (gbs, evs) = self.encode_many_wires(&xs, &ms)?;
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

    fn receive_many(
            &mut self,
            moduli: &[u16],
            channel: &mut Channel,
        ) -> swanky_error::Result<Vec<Self::Item>> {
        todo!()
    }
    fn encode_many(
            &mut self,
            values: &[u16],
            moduli: &[u16],
            channel: &mut Channel,
        ) -> swanky_error::Result<Vec<Self::Item>> {
        todo!()
    }
    fn constant(&mut self, x: u16, q: u16, channel: &mut Channel) -> swanky_error::Result<AuthenticatedWire> {
        todo!()
    }

    fn output(&mut self, X: &AuthenticatedWire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        todo!()
    }
}

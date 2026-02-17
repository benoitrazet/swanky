//! Garbler in Authenticated Garbling
use crate::{preprocess::f_preprocessing, ps::PartyGarbler};
use crate::wire::AuthenticatedWireMod2;
use fancy_garbling::{
    AllWire, BinaryBundle, Fancy, FancyBinary, HasModulus, WireLabel, check_binary,
    util::u128_to_bits,
};
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use swanky_channel::Channel;
use vectoreyes::{SimdBase, U8x16};
/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<RNG, Wire> {
    deltas: HashMap<u16, Wire>, // map from modulus to associated delta wire-label.
    current_output: usize,
    current_gate: usize,
    zero_input_wires: Vec<AuthenticatedWireMod2<PartyGarbler>>,
    authenticated_wires: Vec<AuthenticatedWireMod2<PartyGarbler>>,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore, Wire: WireLabel> Garbler<RNG, Wire> {
    /// Create a new garbler.
    pub fn new(rng: RNG) -> Self {
        Garbler {
            deltas: HashMap::new(),
            current_gate: 0,
            current_output: 0,
            zero_input_wires: Vec::new(),
            authenticated_wires: Vec::new(),
            rng,
        }
    }

    /// The current non-free gate index of the garbling computation
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// Create a delta if it has not been created yet for this modulus, otherwise just
    /// return the existing one.
    pub fn delta(&mut self, q: u16) -> Wire {
        if let Some(delta) = self.deltas.get(&q) {
            return delta.clone();
        }
        let w = Wire::rand_delta(&mut self.rng, q);
        self.deltas.insert(q, w.clone());
        w
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Get the deltas, consuming the Garbler.
    ///
    /// This is useful for reusing wires in multiple garbled circuit instances.
    pub fn get_deltas(self) -> HashMap<u16, Wire> {
        self.deltas
    }

    /// Send a wire over the established channel.
    pub fn send_wire(&mut self, wire: &Wire, channel: &mut Channel) -> swanky_error::Result<()> {
        channel.write(&wire.to_repr())?;
        Ok(())
    }

    /// Encode a wire, producing the zero wire as well as the encoded value.
    pub fn encode_wire(&mut self, val: u16, modulus: u16) -> (Wire, Wire) {
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
    ) -> swanky_error::Result<(Vec<Wire>, Vec<Wire>)> {
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
    ) -> swanky_error::Result<(BinaryBundle<Wire>, BinaryBundle<Wire>)> {
        let xs = u128_to_bits(val, nbits);
        let ms = vec![2; nbits];
        let (gbs, evs) = self.encode_many_wires(&xs, &ms)?;
        Ok((BinaryBundle::new(gbs), BinaryBundle::new(evs)))
    }
}

impl<RNG> FancyBinary for Garbler<RNG, AllWire>
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

impl<RNG: RngCore + CryptoRng, Wire: WireLabel> Fancy for Garbler<RNG, Wire> {
    type Item = Wire;

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
    fn constant(&mut self, x: u16, q: u16, channel: &mut Channel) -> swanky_error::Result<Wire> {
        todo!()
    }

    fn output(&mut self, X: &Wire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        todo!()
    }
}

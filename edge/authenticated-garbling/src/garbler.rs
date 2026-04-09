//! Garbler in Authenticated Garbling
use crate::mux;
use crate::preprocesser::{f_preprocessing, wire::PreProcessedWire};
use crate::ps::PartyGarbler;
use crate::unifier::{CircuitExecutor, CircuitExecutorItem};
use crate::wire::AuthenticatedWireMod2;
use fancy_garbling::{
    BinaryBundle, Fancy, FancyBinary,WireLabel, WireMod2, util::u128_to_bits,
};

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
    delta: Option<WireMod2>, // delta wire-label.
    current_wire_index: usize,
    preprocessed_wires_map: HashMap<usize, PreProcessedWire<PartyGarbler>>,
    known_triples_map: HashMap<usize, PreProcessedWire<PartyGarbler>>,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Garbler<RNG> {
    /// Create a new garbler.
    pub fn new(rng: RNG) -> swanky_error::Result<Self> {
        Ok(Garbler {
            delta: None,
            current_wire_index: 0,
            preprocessed_wires_map: HashMap::new(),
            known_triples_map: HashMap::new(),
            rng,
        })
    }

    /// Create a delta if it has not been created yet for this modulus, otherwise just
    /// return the existing one.
    pub fn delta(&mut self) -> WireMod2 {
        match self.delta {
            Some(d) => d,
            None => {
                let w = WireMod2::rand_delta(&mut self.rng, 2);
                self.delta = Some(w);
                w
            }
        }
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
    pub fn preprocess_circuit(
        &mut self,
        circuit: &impl Fn(
            &mut CircuitExecutor<PartyGarbler, RNG>,
            BinaryBundle<CircuitExecutorItem<PartyGarbler>>,
            BinaryBundle<CircuitExecutorItem<PartyGarbler>>,
            &mut Channel,
        )
            -> swanky_error::Result<BinaryBundle<CircuitExecutorItem<PartyGarbler>>>,
        input_size: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        let mut and_generator = AndTripleGenerator::new(channel, &mut self.rng)?;
        let (preprocessed_wires_map, known_triples_map, _) = f_preprocessing(
            &circuit,
            &mut and_generator,
            input_size,
            channel,
            &mut self.rng,
        )?;
        self.preprocessed_wires_map = preprocessed_wires_map;
        self.known_triples_map = known_triples_map;
        self.delta = Some(WireMod2::from_repr(and_generator.delta(), 2));
        Ok(())
    }

    /// Get the deltas, consuming the Garbler.
    ///
    /// This is useful for reusing wires in multiple garbled circuit instances.
    pub fn get_delta(&self) -> WireMod2 {
        self.delta.unwrap()
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
        let delta = self.delta();
        let enc = zero + delta * u16::from(masked_val);
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
            self.get_delta().to_repr(),
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
        let la1 = la0.wire_label() + self.get_delta();
        // This wire label is L_{β,1} = L_{β,0} + Δ
        let lb1 = lb0.wire_label() + self.get_delta();

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
        let delta_bit_a = mux(la0.auth_share().bit(), 0.into(), self.get_delta().to_repr());
        // Compute Δ_rβ := Δ x r_β: if r_β is 0, then this value is 0, otherwise its Δ
        let delta_bit_b = mux(lb0.auth_share().bit(), 0.into(), self.get_delta().to_repr());
        // Compute Δ_rγ := Δ x r_γ: if r_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c = mux(lc0_share.bit(), 0.into(), self.get_delta().to_repr());
        // Compute Δ_r*γ := Δ x r*_γ: if r*_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c_triple = mux(lc0_triple.bit(), 0.into(), self.get_delta().to_repr());

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

        Ok(AuthenticatedWireMod2 {
            wire_label: WireMod2::from_repr(lc0, 2),
            auth_share: lc0_share,
            index,
        })
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let index = self.current_wire_index();
        AuthenticatedWireMod2 {
            // L_{γ,0} = L_{α,0} + L_{β,0}
            wire_label: x.wire_label() + y.wire_label(),
            // TODO: This is already computed in preprocessing, maybe re-use it?
            //       although i am not sure if the storage is worth it.
            auth_share: x.auth_share() ^ y.auth_share(),
            index,
        }
    }

    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWireMod2 {
            // Negation of a wire is just a matter of adding Δ
            wire_label: x.wire_label() + self.get_delta(),
            // The authenticated share is not affected by negation
            auth_share: x.auth_share(),
            // The index of the wire does not change, this is consistent
            // with how this wire is assigned an index in preprocessing.
            index: x.index(),
        }
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
            self.get_delta().to_repr(),
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
    fn constant(
        &mut self,
        x: u16,
        _q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<AuthenticatedWire> {
        // We haven't implemented a way to take advantage of constant wires
        // in FancyBinary. So they need to be treated as input wires.
        let zero = WireMod2::rand(&mut self.rng, 2);
        let index = self.current_wire_index();
        // Constant wires get their own dedicated authenticated share just like
        // an input wire.
        let auth_share = self.get_current_wire_share(index);
        let wire = zero + self.get_delta() * x;
        // Send the correct wire label to the evaluator
        channel.write(&wire.to_repr())?;
        // Store the authenticate wire as the zero wire label and the authenticated share.
        Ok(AuthenticatedWireMod2 {
            wire_label: zero,
            auth_share,
            index,
        })
    }

    fn output(
        &mut self,
        x: &AuthenticatedWire,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        let auth_share: AuthShare<PartyGarbler> = x.auth_share();
        let mut out = Vec::with_capacity(1);
        AuthShareGenerator::open_with_delta(
            &[auth_share],
            self.get_delta().to_repr(),
            &mut out,
            channel,
        )?;
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
            self.get_delta().to_repr(),
            &mut outputs,
            channel,
        )?;
        Ok(Some(outputs.iter().map(|o| u16::from(*o)).collect()))
    }
}

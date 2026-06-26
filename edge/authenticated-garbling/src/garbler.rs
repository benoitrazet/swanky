use crate::GarblerValidator;
use crate::preprocesser::WirePreProcessor;
use crate::preprocesser::f_preprocessing;
use crate::ps::PartyGarbler;
use crate::wire::AuthenticatedWireMod2;
use fancy_garbling::Circuit;
use fancy_garbling::CircuitInputMapper;
use fancy_garbling::FancyOutput;
use fancy_garbling::circuit_analyzer::CircuitAnalyzer;
use fancy_garbling::{Fancy, FancyBinary, FancyEncode, WireLabel, WireMod2};

use rand::{CryptoRng, RngCore};
use swanky_authenticated_bits::and_triples::AndTripleGenerator;
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::WrapErr;
use swanky_error::{ErrorKind, Result, ensure};
use swanky_field::FiniteRing;
use swanky_field_binary::F2BitDeserializer;
use swanky_field_binary::F2BitSerializer;
use swanky_field_binary::{F2, F128b};
use swanky_serialization::SequenceDeserializer;
use swanky_serialization::SequenceSerializer;
use vectoreyes::U8x16;

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;

/// The authenticated garbler.
pub struct Garbler<RNG> {
    // The number of input wires to the circuit
    ninputs: usize,
    // The garbler's Δ.
    delta: WireMod2,
    // A random wirelabel denoting zero. Used to make negations free.
    // The one label that can be derived out of this label is also used for
    // constant 1 gates.
    zero: WireMod2,
    // A random wirelabel denoting zero. Used to make constants free.
    zero_constant: WireMod2,
    // The index of the current AND gate. Used as the tweak when hashing
    // wirelabels in the AND gate garbling.
    and_gate_index: usize,
    // A vector of authenticated shares, one per input wire and AND gate output.
    // Corresponds to〈r_w, s_w〉from the paper.
    auth_shares: Vec<AuthShare<PartyGarbler>>,
    // The index of the current authenticated share we're using.
    auth_shares_index: usize,
    // A vector of fixed authenticated shares for AND gate wires. Each share is
    // set such that it is equal to the AND of the incoming wire shares.
    // Corresponds to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: Vec<AuthShare<PartyGarbler>>,
    // The index of the current AND authenticated share we're using.
    and_auth_shares_index: usize,
    // A vector that stores the garbling gates.
    gates: Vec<(U8x16, U8x16)>,
    // A vector that stores the lsb of the 0 wire label associated with AND gates.
    gate_bits: Vec<F2>,
    // The wire material that the garbler computes offline
    offline_wires: Vec<AuthenticatedWire>,
    // The index of the current offline wire
    wires_offline_index: usize,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Garbler<RNG> {
    /// Create a new garbler for a given circuit.
    pub fn new<
        C: CircuitInputMapper<CircuitAnalyzer>
            + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
            + CircuitInputMapper<GarblerValidator<RNG>>
            + CircuitInputMapper<Self>,
    >(
        circuit: &C,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> Result<(Self, <C as Circuit<Garbler<RNG>>>::Output)> {
        let delta = AndTripleGenerator::<PartyGarbler>::generate_valid_delta(&mut rng);
        // The garbler pre-generates two constant wire-labels
        // - The one wire label that is used for negation and garbling constant 1 gates.
        // - The zero wire label used for garbling constant 0 gates.
        // These wire labels are used to make negation and constant gates free.
        // Because they are uncorrelated, the evaluator learns nothing about the garbler's
        // private delta value.
        let zero = WireMod2::rand(&mut rng, 2);
        let zero_constant = WireMod2::rand(&mut rng, 2);
        let one = WireMod2::from_repr(zero.to_repr() ^ delta, 2);

        let mut and_generator = AndTripleGenerator::new_with_delta(delta, channel, &mut rng)?;
        let (auth_shares, known_triples) =
            f_preprocessing(circuit, &mut and_generator, channel, &mut rng)?;
        let nands = known_triples.len();
        let ninputs: usize = <C as CircuitInputMapper<CircuitAnalyzer>>::ninputs(circuit);
        channel.write(&one.to_repr())?;
        channel.write(&zero_constant.to_repr())?;
        let garbler = Garbler {
            ninputs,
            delta: WireMod2::from_repr(delta, 2),
            zero,
            zero_constant,
            and_gate_index: 0,
            auth_shares,
            auth_shares_index: 0,
            and_auth_shares: known_triples,
            and_auth_shares_index: 0,
            gates: Vec::with_capacity(nands),
            gate_bits: Vec::with_capacity(nands),
            offline_wires: Vec::new(),
            wires_offline_index: 0,
            rng,
        };
        let mut garbler = garbler.offline()?;
        let offline_wires = garbler.offline_wires();
        let outputs = circuit.execute(
            &mut garbler,
            CircuitInputMapper::<Self>::map(circuit, offline_wires),
            channel,
        )?;
        Ok((garbler, outputs))
    }

    fn next_and_gate_index(&mut self) -> usize {
        let current = self.and_gate_index;
        self.and_gate_index += 1;
        current
    }

    fn next_auth_share(&mut self) -> AuthShare<PartyGarbler> {
        let share = self.auth_shares[self.auth_shares_index];
        self.auth_shares_index += 1;
        share
    }
    fn next_and_auth_share(&mut self) -> AuthShare<PartyGarbler> {
        let share = self.and_auth_shares[self.and_auth_shares_index];
        self.and_auth_shares_index += 1;
        share
    }
    fn next_offline_wire(&mut self) -> AuthenticatedWire {
        let wire = self.offline_wires[self.wires_offline_index];
        self.wires_offline_index += 1;
        wire
    }
    pub(crate) fn auth_share_at_index(&self, index: usize) -> AuthShare<PartyGarbler> {
        self.auth_shares[index]
    }

    pub(crate) fn and_auth_share_at_index(&self, index: usize) -> AuthShare<PartyGarbler> {
        self.and_auth_shares[index]
    }

    pub(crate) fn delta(&self) -> U8x16 {
        self.delta.to_repr()
    }
    pub(crate) fn send_garbling_material(&self, channel: &mut Channel) -> Result<()> {
        // The garbler sends out all the gate material that they computed offline
        let bit_ser: F2BitSerializer = SequenceSerializer::new(&mut channel.as_std_io()).wrap_err(
            ErrorKind::InitializationError,
            "Failed to initialize sequence serializer.",
        )?;
        // Send the lsb of 0 wire label
        bit_ser
            .write_vec(channel.as_std_io(), &self.gate_bits)
            .wrap_err(
                ErrorKind::SerializationError,
                "Failed to write serialized bits.",
            )?;
        // Send the garbled gates
        for (g0, g1) in self.gates.iter() {
            channel.write(g0)?;
            channel.write(g1)?;
        }
        Ok(())
    }
    /// This function allows the garbler to encode wire labels offline prior
    /// to receiving the evaluator's values. By doing this we greatly improve
    /// the performance of the protocol.
    fn offline(self) -> Result<Self> {
        let mut gb: Garbler<RNG> = self;
        let input_wires: Vec<AuthenticatedWire> = (0..gb.ninputs)
            .map(|_| {
                AuthenticatedWire::new_without_mask(
                    WireMod2::rand(&mut gb.rng, 2),
                    gb.next_auth_share(),
                )
            })
            .collect();
        gb.offline_wires = input_wires;
        Ok(gb)
    }
    /// Returns the offline wires for the purpose for circuit execution
    pub fn offline_wires(&self) -> Vec<AuthenticatedWire> {
        self.offline_wires.clone()
    }
    // Send the wirelabel `L_b` associated with the masked value `b` to the evaluator returning a vector of the
    // corresponding `FinalizedWire` values.
    //
    // This corresponds to pieces of Steps 3 and 4 in Figure 3 of the paper.
    fn encode_wirelabels(
        &mut self,
        wires: &[AuthenticatedWire],
        masked_values: Vec<F2>,
        channel: &mut Channel,
    ) -> Result<Vec<AuthenticatedWire>> {
        let mut result = Vec::new();
        for (masked_value, wire) in masked_values.iter().zip(wires.iter()) {
            // Use masked values `x_w + λ_w` and zero wirelabels `L_0` to create
            // wirelabels `L_{x_w + λ_w}`, and send these to the evaluator.
            let wirelabel = wire.wire_label()
                + WireMod2::from_repr(U8x16::from(*masked_value * F128b::from(self.delta())), 2);
            channel.write(&wirelabel.to_repr())?;
            result.push(AuthenticatedWire::new(
                *masked_value,
                wirelabel,
                wire.auth_share(),
            ));
        }
        Ok(result)
    }

    /// A function that validates the authenticated garbling computation before
    /// opening the output share.
    ///
    /// Prior to revealing the result of the computation, the garbler and evaluator
    /// need to validate the authenticated AND gates. In the case of the garbler, this
    /// involved locally traversing the circuit in order to compute those validation bits
    /// from the wire masked values that the evaluator sends.
    pub fn validate<C: CircuitInputMapper<GarblerValidator<RNG>>>(
        self,
        circuit: &C,
        input_wires: Vec<AuthenticatedWire>,
        channel: &mut Channel,
    ) -> Result<Garbler<RNG>> {
        let nands = self.and_auth_shares.len();
        // Receive the masked values from the Evaluator
        let mut bit_deser: F2BitDeserializer = SequenceDeserializer::new(channel.as_std_io())
            .wrap_err(
                ErrorKind::InitializationError,
                "Failed to create sequence deserializer.",
            )?;
        let lc_values = bit_deser.read_vector(channel.as_std_io(), nands).wrap_err(
            ErrorKind::SerializationError,
            "Failed to read serialized bits.",
        )?;
        let delta = self.delta();
        // Create a finalizer using the pre-computed wires
        let mut validator = GarblerValidator::new(self, input_wires.clone(), lc_values);

        // Locally run the circuit to correctly construct the validation shares
        Channel::with(std::io::empty(), {
            |c| circuit.execute(&mut validator, circuit.map(input_wires), c)
        })?;

        let mut validation_bits = Vec::with_capacity(nands);
        // The parties then open the share c_γ
        AuthShareGenerator::open_with_delta(
            validator.validation_shares(),
            delta,
            &mut validation_bits,
            channel,
        )?;

        let validation_failures: Vec<&F2> =
            validation_bits.iter().filter(|&&x| x == F2::ONE).collect();
        ensure!(
            validation_failures.is_empty(),
            ErrorKind::OtherError,
            "Evaluator's authentication validation check failed"
        );
        Ok(validator.garbler())
    }
    /// Validate the computation and reveal the outputs
    pub fn finalize<C: CircuitInputMapper<GarblerValidator<RNG>>>(
        self,
        circuit: &C,
        input_wires: Vec<AuthenticatedWire>,
        output_wires: &[AuthenticatedWire],
        channel: &mut Channel,
    ) -> Result<Option<Vec<u16>>> {
        let mut gb = self.validate(circuit, input_wires, channel)?;
        gb.outputs(output_wires, channel)
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
        _channel: &mut Channel,
    ) -> Result<Self::Item> {
        // This index is called γ in the paper
        let index = self.next_and_gate_index();
        // This is the share for wire label L_{γ,0}
        let lc_share = self.next_auth_share();
        // This is the and triple share for wire label L_{γ,0}
        let lc_triple = self.next_and_auth_share();

        // Compute l1 from l0 for both inputs
        //
        // This wire label is L_{α,1} = L_{α,0} + Δ
        let la1 = la0.wire_label() + self.delta;
        // This wire label is L_{β,1} = L_{β,0} + Δ
        let lb1 = lb0.wire_label() + self.delta;

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
        let delta_bit_a = U8x16::from(la0.auth_share().bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_rβ := Δ x r_β: if r_β is 0, then this value is 0, otherwise its Δ
        let delta_bit_b = U8x16::from(lb0.auth_share().bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_rγ := Δ x r_γ: if r_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c = U8x16::from(lc_share.bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_r*γ := Δ x r*_γ: if r*_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c_triple = U8x16::from(lc_triple.bit() * F128b::from(self.delta.to_repr()));

        // Gate_{γ,0} = H(L_{α,0}, γ) + H(L_{α,1}, γ) + K[s_β] + Δ_rβ
        let gate0 = h_la0 ^ h_la1 ^ key_b ^ delta_bit_b;
        // Gate_{γ,1} = H(L_{β,0}, γ) + H(L_{β,1}, γ) + K[s_α] + Δ_rα + L_{α,0}
        let gate1 = h_lb0 ^ h_lb1 ^ key_a ^ delta_bit_a ^ la0.wire_label().to_repr();
        // L_{γ,0} = H(L_{α,0}, γ) + H(L_{β,0}, γ) + K[s_γ] + Δ_rγ + K[s*_γ] + Δ_r*γ
        let lc0 = h_la0 ^ h_lb0 ^ key_c ^ delta_bit_c ^ key_c_triple ^ delta_bit_c_triple;
        // b_γ = lsb(L_{γ,0})
        let bit_c = F128b::from(lc0).lsb();

        self.gates.push((gate0, gate1));
        self.gate_bits.push(bit_c);

        Ok(AuthenticatedWire::new_without_mask(
            WireMod2::from_repr(lc0, 2),
            lc_share,
        ))
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        AuthenticatedWire::new_without_mask(
            x.wire_label() + y.wire_label(),
            x.auth_share() ^ y.auth_share(),
        )
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWire::new_without_mask(
            WireMod2::from_repr(x.wire_label().to_repr() ^ self.zero.to_repr(), 2),
            x.auth_share(),
        )
    }
}

impl<RNG: RngCore + CryptoRng> Fancy for Garbler<RNG> {
    type Item = AuthenticatedWire;

    fn constant(
        &mut self,
        value: u16,
        _q: u16,
        _channel: &mut Channel,
    ) -> Result<AuthenticatedWire> {
        let constant = F2::try_from(value).expect("constant must be boolean");
        let share = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta.to_repr());
        // Because the garbler is sending uncorrelated zero and one wire labels to the evaluator for constant gates and free negation,
        // they have to be careful which zero wire label to use for each constant gate so that it correlates
        // with the one that the evaluator is using.
        let wire_label = if constant == F2::ONE {
            // If the value of the gate is 1, then the garbler needs to user the wire label
            // associated with the constant 1 wire label that they sent out to the evaluator,
            // i.e. the zero value that they generated for that wire and free negations.
            self.zero
        } else {
            // Otherwise, the garbler needs to use the same zero wire label as the one they sent
            // to the evaluator, i.e. the wire label specifically generated for zero constant gates.
            self.zero_constant
        };
        Ok(AuthenticatedWire::new(constant, wire_label, share))
    }
}

impl<RNG: RngCore + CryptoRng> FancyEncode for Garbler<RNG> {
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> Result<Vec<<Self as Fancy>::Item>> {
        assert_eq!(values.len(), moduli.len());

        self.send_garbling_material(channel)?;

        let offline_wires: Vec<AuthenticatedWire> = (0..moduli.len())
            .map(|_| self.next_offline_wire())
            .collect();
        let my_auth_shares: Vec<AuthShare<PartyGarbler>> =
            offline_wires.iter().map(|w| w.auth_share()).collect();

        // Open the evaluator's shares `[s_w]` using these shares.
        let mut their_bits = Vec::with_capacity(values.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &my_auth_shares,
            self.delta(),
            &mut their_bits,
            channel,
        )?;

        // Compute masked values `x_w ⊕ λ_w := x_w ⊕ (s_w ⊕ r_w)`.
        let my_masked_values = their_bits
            .into_iter()
            .zip(my_auth_shares.iter().zip(values.iter()))
            .map(|(theirs, (mine, value))| {
                F2::try_from(*value)
                    .wrap_err(ErrorKind::OtherError, "Invalid value, must be boolean")
                    .map(|value| theirs + mine.bit() + value)
            })
            .collect::<Result<Vec<_>>>()?;

        // Send `x_w ⊕ λ_w` to the evaluator.
        for masked_value in my_masked_values.iter() {
            channel.write(masked_value)?;
        }

        self.encode_wirelabels(&offline_wires, my_masked_values, channel)
    }

    fn receive_many(&mut self, moduli: &[u16], channel: &mut Channel) -> Result<Vec<Self::Item>> {
        let offline_wires: Vec<AuthenticatedWire> = (0..moduli.len())
            .map(|_| self.next_offline_wire())
            .collect();
        let my_auth_shares: Vec<AuthShare<PartyGarbler>> =
            offline_wires.iter().map(|w| w.auth_share()).collect();

        // Open the garbler's shares `[r_w]` using these shares.
        AuthShareGenerator::open_my_shares(&my_auth_shares, channel)?;

        // Receive `y_w ⊕ λ_w := y_w ⊕ (s_w ⊕ r_w)` from the evaluator.
        let their_masked_values = (0..moduli.len())
            .map(|_| channel.read::<F2>())
            .collect::<Result<Vec<_>>>()?;

        self.encode_wirelabels(&offline_wires, their_masked_values, channel)
    }
}

impl<RNG: RngCore + CryptoRng> FancyOutput for Garbler<RNG> {
    fn output(&mut self, x: &AuthenticatedWire, channel: &mut Channel) -> Result<Option<u16>> {
        Ok(self
            .outputs(core::slice::from_ref(x), channel)?
            .map(|xs| xs[0]))
    }

    fn outputs(
        &mut self,
        x: &[AuthenticatedWire],
        channel: &mut Channel,
    ) -> Result<Option<Vec<u16>>> {
        let auth_shares = x.iter().map(|wire| wire.auth_share()).collect::<Vec<_>>();
        AuthShareGenerator::open_my_shares(&auth_shares, channel)?;
        Ok(None)
    }
}

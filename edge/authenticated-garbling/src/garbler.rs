use crate::GarblerFinalizer;
use crate::finalizer::FinalizedWire;
use crate::preprocesser::WirePreProcessor;
use crate::preprocesser::f_preprocessing;
use crate::ps::PartyGarbler;
use crate::wire::AuthenticatedWireMod2;
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
    // The garbler's Δ.
    delta: WireMod2,
    // A random wirelabel denoting zero. Used to make negations free.
    zero: WireMod2,
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
    // A vector that stores the garbling gate bits.
    gate_bits: Vec<F2>,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Garbler<RNG> {
    /// Create a new garbler for a given circuit.
    pub fn new<
        'a,
        C: CircuitInputMapper<CircuitAnalyzer>
            + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
            + CircuitInputMapper<GarblerFinalizer<'a, RNG>>,
    >(
        circuit: &C,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> Result<Self>
    where
        RNG: 'a,
    {
        let delta = AndTripleGenerator::<PartyGarbler>::generate_valid_delta(&mut rng);
        let zero = WireMod2::rand(&mut rng, 2);
        let one = WireMod2::from_repr(zero.to_repr() ^ delta, 2);

        let mut and_generator = AndTripleGenerator::new_with_delta(delta, channel, &mut rng)?;
        let (auth_shares, known_triples) =
            f_preprocessing(circuit, &mut and_generator, channel, &mut rng)?;
        let nands = known_triples.len();
        channel.write(&one.to_repr())?;
        Ok(Garbler {
            delta: WireMod2::from_repr(delta, 2),
            zero,
            and_gate_index: 0,
            auth_shares,
            auth_shares_index: 0,
            and_auth_shares: known_triples,
            and_auth_shares_index: 0,
            gates: Vec::with_capacity(nands),
            gate_bits: Vec::with_capacity(nands),
            rng,
        })
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

        bit_ser.write_vector(channel.as_std_io(), &self.gate_bits)?;

        for (g0, g1) in self.gates.iter() {
            channel.write(g0)?;
            channel.write(g1)?;
        }
        Ok(())
    }
    /// This function allows the garbler to encode wire labels offline prior
    /// to receiving the evaluator's values. By doing this we greatly improve
    /// the performance of the protocol.
    pub fn encode_offline(&mut self, ninputs: usize) -> Result<Vec<AuthenticatedWire>> {
        let input_wires: Vec<AuthenticatedWire> = (0..ninputs)
            .map(|_| {
                AuthenticatedWire::new_without_mask(
                    WireMod2::rand(&mut self.rng, 2),
                    self.next_auth_share(),
                )
            })
            .collect();
        Ok(input_wires)
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
    ) -> swanky_error::Result<Vec<FinalizedWire>> {
        let mut result = Vec::new();
        for (masked_value, wire) in masked_values.iter().zip(wires.iter()) {
            // Use masked values `x_w + λ_w` and zero wirelabels `L_0` to create
            // wirelabels `L_{x_w + λ_w}`, and send these to the evaluator.
            let wirelabel = wire.wire_label()
                + WireMod2::from_repr(U8x16::from(*masked_value * F128b::from(self.delta())), 2);
            channel.write(&wirelabel.to_repr())?;
            result.push(FinalizedWire::new(*masked_value, wire.auth_share()));
        }
        Ok(result)
    }
    /// Receive the evaluators wire labels online
    pub fn receive_many(
        &mut self,
        wires_offline: &[AuthenticatedWire],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<FinalizedWire>> {
        let my_auth_shares: Vec<AuthShare<PartyGarbler>> =
            wires_offline.iter().map(|w| w.auth_share()).collect();

        // Open the garbler's shares `[r_w]` using these shares.
        AuthShareGenerator::open_my_shares(&my_auth_shares, channel)?;

        // Receive `y_w ⊕ λ_w := y_w ⊕ (s_w ⊕ r_w)` from the evaluator.
        let their_masked_values = (0..moduli.len())
            .map(|_| channel.read::<F2>())
            .collect::<Result<Vec<_>>>()?;

        self.encode_wirelabels(wires_offline, their_masked_values, channel)
    }
    /// Encode and send the garblers wire labels online
    pub fn encode_many(
        &mut self,
        wires_offline: &[AuthenticatedWire],
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<FinalizedWire>> {
        assert_eq!(values.len(), moduli.len());

        self.send_garbling_material(channel)?;

        let my_auth_shares: Vec<AuthShare<PartyGarbler>> =
            wires_offline.iter().map(|w| w.auth_share()).collect();

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

        self.encode_wirelabels(&wires_offline, my_masked_values, channel)
    }

    /// A function that finalizes the authenticated garbling computation before
    /// opening the output share.
    ///
    /// Prior to revealing the result of the computation, the garbler and evaluator
    /// need to validate the authenticated AND gates. In the case of the garbler, this
    /// involved locally traversing the circuit in order to compute those validation bits
    /// from the wire masked values that the evaluator sends.
    pub fn finalize<
        'a,
        'b: 'a,
        C: CircuitInputMapper<CircuitAnalyzer>
            + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
            + CircuitInputMapper<GarblerFinalizer<'a, RNG>>,
    >(
        &'b self,
        circuit: &C,
        input_wires: Vec<FinalizedWire>,
        channel: &mut Channel,
    ) -> Result<()>
    where
        RNG: 'a,
    {
        let nands = self.and_auth_shares.len();
        // Receive the masked values from the Evaluator
        let mut bit_deser: F2BitDeserializer = SequenceDeserializer::new(channel.as_std_io())
            .wrap_err(
                ErrorKind::InitializationError,
                "Failed to create sequence deserializer.",
            )?;
        let lc_values = bit_deser.read_vector(channel.as_std_io(), nands)?;
        // Create a finalizer using the pre-computed wires
        let mut finalizer = GarblerFinalizer::new(self, input_wires.clone(), lc_values);

        // Locally run the circuit to correctly construct the validation shares
        circuit.execute(
            &mut finalizer,
            <C as CircuitInputMapper<GarblerFinalizer<'a, RNG>>>::map(circuit, input_wires),
            channel,
        )?;

        let mut validation_bits = Vec::with_capacity(nands);
        // The parties then open the share c_γ
        AuthShareGenerator::open_with_delta(
            finalizer.validation_shares(),
            self.delta(),
            &mut validation_bits,
            channel,
        )?;

        let validation_failures: Vec<&F2> =
            validation_bits.iter().filter(|&&x| x == F2::ONE).collect();
        ensure!(
            validation_failures.len() == 0,
            ErrorKind::OtherError,
            "Evaluator's authentication validation check failed"
        );
        Ok(())
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

        Ok(AuthenticatedWire::new(constant, self.zero, share))
    }
}

impl<RNG: RngCore + CryptoRng> FancyEncode for Garbler<RNG> {
    fn encode_many(
        &mut self,
        _values: &[u16],
        _moduli: &[u16],
        _channel: &mut Channel,
    ) -> Result<Vec<<Self as Fancy>::Item>> {
        unimplemented!(
            "The garbler needs to be calling its own special encoding function to use its offline generated material!"
        );
    }

    fn receive_many(&mut self, _moduli: &[u16], _channel: &mut Channel) -> Result<Vec<Self::Item>> {
        unimplemented!(
            "The garbler needs to be calling its own special receive function to use its offline generated material!"
        );
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

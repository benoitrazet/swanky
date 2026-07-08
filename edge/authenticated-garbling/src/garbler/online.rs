use crate::{
    GarblerValidator, garbler::AuthenticatedWire, ps::PartyGarbler, vec_wrapper::VecWrapper,
};
use fancy_garbling::{WireLabel, WireMod2};
use fancy_traits::{Fancy, FancyEncode};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_field_binary::{F2, F2BitDeserializer, F128b};
use swanky_serialization::SequenceDeserializer;
use vectoreyes::U8x16;

/// The garbler's online phase.
pub struct GarblerOnline {
    // The garbler's Δ.
    delta: WireMod2,
    // A vector of authenticated shares, one per input wire and AND gate output.
    // Corresponds to〈r_w, s_w〉from the paper.
    auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
    // A vector of fixed authenticated shares for AND gate wires. Each share is
    // set such that it is equal to the AND of the incoming wire shares.
    // Corresponds to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
    // The wire material that the garbler computes offline
    offline_wires: VecWrapper<AuthenticatedWire>,
}

impl GarblerOnline {
    pub(crate) fn new(
        delta: WireMod2,
        auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
        and_auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
        offline_wires: VecWrapper<AuthenticatedWire>,
    ) -> Self {
        Self {
            delta,
            auth_shares,
            and_auth_shares,
            offline_wires,
        }
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
                + WireMod2::from_repr(
                    U8x16::from(*masked_value * F128b::from(self.delta.to_repr())),
                    2,
                );
            channel.write(&wirelabel.to_repr())?;
            result.push(AuthenticatedWire::new(
                *masked_value,
                wirelabel,
                wire.auth_share(),
            ));
        }
        Ok(result)
    }

    pub(crate) fn delta(&self) -> U8x16 {
        self.delta.to_repr()
    }

    /// Finalize the online portion of the computation.
    ///
    /// Prior to revealing the result of the computation, the garbler and
    /// evaluator need to validate the authenticated AND gates. In the case of
    /// the garbler, this involved locally traversing the circuit in order to
    /// compute those validation bits from the wire masked values that the
    /// evaluator sends.
    pub fn finalize(
        self,
        input_wires: &[AuthenticatedWire],
        channel: &mut Channel,
    ) -> Result<GarblerValidator> {
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

        let auth_shares: Vec<_> = self.auth_shares.into();
        Ok(GarblerValidator::new(
            self.delta,
            auth_shares[input_wires.len()..].to_vec(),
            self.and_auth_shares.into(),
            lc_values,
        ))
    }
}

impl FancyEncode for GarblerOnline {
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> Result<Vec<<Self as Fancy>::Item>> {
        assert_eq!(values.len(), moduli.len());

        let offline_wires: Vec<AuthenticatedWire> = (0..moduli.len())
            .map(|_| self.offline_wires.next())
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
            .map(|_| self.offline_wires.next())
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

impl Fancy for GarblerOnline {
    type Item = AuthenticatedWire;

    fn constant(
        &mut self,
        _value: u16,
        _q: u16,
        _channel: &mut Channel,
    ) -> Result<AuthenticatedWire> {
        // TODO: `constant` should _not_ be a part of `Fancy`, but maybe live in
        // a `FancyConstant` trait?
        unimplemented!(
            "In the online phase, we don't do any circuit evaluation, so `constant` should never be called."
        )
    }
}

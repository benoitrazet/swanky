//! Authenticated Garbling's pre-processing functionality.
//!
//! The first step in authenticated garbling consists in pre-processing a fixed
//! circuit in order to give each party shares of wire labels. This pre-processing
//! step is one of the main reasons why authenticated garbling achieves
//! an *online* communication complexity that is "close to" its semi-honest counterpart.
//! See Figure 2 from Katz et al.[^1] for more details.
//!
//! The idea behind pre-processing is to generate random authenticated shares "per wire"[^0] that
//! are input independent and circuit dependent. These shares will later be used for both
//! authentication and garbling during the "online" phase. We consider that these shares are
//! circuit dependent because the output wires of AND gates are associated with two pairs of
//! shares:
//! (1) The regular authenticated shares
//! (2) Correlated authenticated shares that we call AND triples
//! these two pairs of AND shares are combined in the online phase to properly garble and evaluate
//! AND gates. See Figure 2 from Katz et al.[^1] for more details.
//!
//! [^0]: In practice, we only generate these shares for input wires and the output wires
//! of AND gates. The reason is that the construction preserves certain classic Garbled Circuits
//! optimizations and namely free-XORs [^1]. Recall that in free-XOR: $`L_0 \oplus L_1 = \Delta`$.
//!
//! References:
//! [^1]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing Authenticated
//! Garbling for Faster Secure Two-Party Computation".
//! <https://eprint.iacr.org/2018/578.pdf>
//!
use fancy_garbling::{
    BinaryBundle, BinaryGadgets,
    circuit_analyzer::{AnalyzerItem, CircuitAnalyzer},
};
use rand::{CryptoRng, Rng};
use swanky_authenticated_bits::{
    and_triples::{AndTriple, AndTripleGenerator},
    authshares::AuthShare,
};
use swanky_channel::Channel;
use swanky_party::GenericParty;
use vectoreyes::U8x16;

/// Pre-process a circuit for authenticated garbling.
///
/// Authenticated garbling utilizes pre-computed [`AndTriple`]s and [`AuthShare`]s in its "online" portion.
/// This function generates the correct number of such triples and shares for a given circuit of interest and returns
/// the delta value used for that generation. This delta value is party specific, and in the case of the Garbler will
/// be used as the free-XOR delta.
/// The circuit is provided as a closure which takes in a fancy object (in this case an [`CircuitAnalyzer`]) and circuit inputs
/// written as [`BinaryBundle`] over fancy items (in this case [`AnalyzerItem`]), and triples and shares are
/// generated using the provided [`AndTripleGenerator`].
///
/// Note that the fancy circuit passed to this function is generic in the size of the input,
/// this is why we need to pass the input size separately. This fancy circuit is the same one that will
/// be later used for garbling.
pub fn f_preprocessing<P: GenericParty, RNG: CryptoRng + Rng>(
    circuit: impl Fn(
        &mut CircuitAnalyzer,
        BinaryBundle<AnalyzerItem>,
        BinaryBundle<AnalyzerItem>,
        &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<AnalyzerItem>>,
    and_generator: &mut AndTripleGenerator<P>,
    input_size: usize,
    channel: &mut Channel,
    rng: &mut RNG,
) -> swanky_error::Result<(Vec<AndTriple<P>>, Vec<AuthShare<P>>, U8x16)> {
    let mut analyzer = CircuitAnalyzer::new();
    let dummy_wires_self: BinaryBundle<AnalyzerItem> =
        analyzer.bin_encode(0, input_size, channel).unwrap();
    let dummy_wires_other: BinaryBundle<AnalyzerItem> =
        analyzer.bin_receive(input_size, channel).unwrap();

    circuit(&mut analyzer, dummy_wires_self, dummy_wires_other, channel)?;

    let nands = analyzer.nands();
    let mut and_shares = Vec::with_capacity(nands);
    and_generator.generate(nands, &mut and_shares, channel, rng)?;

    let ninputs = analyzer.ninputs();
    let mut auth_shares = Vec::with_capacity(nands + ninputs);
    and_generator.auth_share_generator_mut().generate(
        nands + ninputs,
        &mut auth_shares,
        channel,
        rng,
    )?;
    Ok((and_shares, auth_shares, and_generator.delta()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_garbling::{BinaryGadgets, Fancy, FancyBinary};
    use swanky_party::party_system;
    use swanky_rng::SwankyRng;

    party_system! {
        mod ps {
            PartyA,
            PartyB,
        }
    }
    use ps::{PartyA, PartyB};

    /// Garbler
    ///
    /// This is a type-alias for [`PartyA`] and is useful to clarify the role of a
    /// authenticated shares and and triples.
    pub type Garbler = PartyA;
    /// Evaluator
    ///
    /// This is a type-alias for [`PartyB`] and is useful to clarify the role of a
    /// authenticated shares and and triples.
    pub type Evaluator = PartyB;
    fn fancy_sum<F>(
        f: &mut F,
        garbler_wires: BinaryBundle<F::Item>,
        evaluator_wires: BinaryBundle<F::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<F::Item>>
    where
        F: Fancy + BinaryGadgets + FancyBinary,
    {
        f.bin_addition_no_carry(&garbler_wires, &evaluator_wires, channel)
    }
    #[test]
    fn test_preprocessing_fancy_sum() {
        let input_size = 400;
        let (_shares_gb, _shares_ev) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = SwankyRng::new();
                let mut generator_and_triples = AndTripleGenerator::<Garbler>::new(c, &mut rng)?;
                Ok(f_preprocessing(
                    fancy_sum,
                    &mut generator_and_triples,
                    input_size,
                    c,
                    &mut rng,
                ))
            },
            |c| {
                let mut rng = SwankyRng::new();
                let mut generator_and_triples = AndTripleGenerator::<Evaluator>::new(c, &mut rng)?;
                Ok(f_preprocessing(
                    fancy_sum,
                    &mut generator_and_triples,
                    input_size,
                    c,
                    &mut rng,
                ))
            },
        )
        .unwrap();
    }
}

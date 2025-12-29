//! Authenticated Garbling's pre-processing functionality.
//!
//! The first step in authenticated garbling consists in pre-processing a fixed
//! circuit in order to give each party shares of wire labels. This pre-processing
//! step is one of the main reasons why authenticated garbling achieves
//! an *online* communication complexity that is "close to" its semi-honest counterpart. See Figure 2 in [^1] for more details.
//!
//! The idea behind pre-processing is to generate random authenticated shares "per wire"[^0] that
//! are input independent and circuit dependent. These shares will later be used for both
//! authentication and garbling during the "online" phase. We consider that these shares are
//! circuit dependent because the output wires of AND gates are associated with two pairs of
//! shares:
//! (1) The regular authenticated shares
//! (2) Correlated authenticated shares that we call AND triples
//! these two pairs of AND shares are combined in the online phase to properly garble and evaluate
//! AND gates. See Figure 2 in [^1] for more details.
//!
//! [^0]: In practice, we only generate these shares for input wires and the output wires
//! of AND gates. The reason is that the construction in [1] preserves certain classic Garbled Circuits
//! optimizations and namely free-XORs. Recall that in free-XOR: $L_0 \oplus L_1 = \Delta$.
//!
//! References:
//! [^1]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing Authenticated
//! Garbling for Faster Secure Two-Party Computation".
//! <https://eprint.iacr.org/2018/578.pdf>
//!
use crate::analyzer::{Analyzer, AnalyzerError, AnalyzerItem};
use eyre::Ok;
use fancy_garbling::{BinaryBundle, FancyInput};
use rand::{CryptoRng, Rng};
use swanky_adversary::Malicious;
use swanky_authenticated_bits::{
    and_triples::{AndTriple, AndTripleGenerator},
    authshares::{AuthShare, AuthShareGenerator},
};
use swanky_channel::Channel;
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender};
use swanky_party::Party;
use vectoreyes::U8x16;

/// Pre-process a circuit for authenticated garbling.
///
/// Authenticated garbling utilizes pre-computed [`AndTriple`]s and [`AuthShare`]s in its "online" portion. 
/// This function generates the correct number of such triples and shares for a given circuit of interest. 
/// The circuit is provided as a closure which takes in a fancy object (in this case an [`Analyzer`]) and circuit inputs
/// written as [`BinaryBundle`] over fancy items ( in this case [`AnalyzerItem`]), and triples and shares are 
/// generated using the provided [`AndTripleGenerator`].

/// The pre-processing function
///
/// This function takes in
/// - circuit: a fancy circuit written as a closure.
/// - and_generator: An And Triple Generator that has been pre-initialized.
/// - auth_generator: An Authenticated Share Generator that has been pre-initialized.
/// - input_size: The size in bits of the parties inputs to the circuit.
/// This function returns:
/// - A vector of AndTriples that are party dependent. This protocol generates as many
/// AndTriples as there are AND gates.
/// - A vector of AuthShare that are party dependent. This protocol generates as many
/// AuthShare as there are AND gates and input wires.
pub fn f_preprocessing<
    P: Party,
    RNG: CryptoRng + Rng,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
>(
    circuit: impl Fn(
        &mut Analyzer,
        BinaryBundle<AnalyzerItem>,
        BinaryBundle<AnalyzerItem>,
    ) -> Result<BinaryBundle<AnalyzerItem>, AnalyzerError>,
    and_generator: &mut AndTripleGenerator<P, OTS, OTR>,
    auth_generator: &mut AuthShareGenerator<P, OTS, OTR>,
    input_size: usize,
    channel: &mut Channel,
    rng: &mut RNG,
) -> eyre::Result<(Vec<AndTriple<P>>, Vec<AuthShare<P>>)> {
    let mut analyzer = Analyzer::new();
    let dummy_wires_self: BinaryBundle<AnalyzerItem> = analyzer.bin_encode(0, input_size).unwrap();
    let dummy_wires_other: BinaryBundle<AnalyzerItem> = analyzer.bin_receive(input_size).unwrap();

    circuit(&mut analyzer, dummy_wires_self, dummy_wires_other)?;

    let nands = analyzer.nands();
    let mut and_shares = Vec::with_capacity(nands);
    and_generator.generate(nands, &mut and_shares, channel, rng)?;

    let ninputs = analyzer.ninputs();
    let mut auth_shares = Vec::with_capacity(ninputs);
    auth_generator.generate(nands + ninputs, &mut auth_shares, channel, rng)?;

    Ok((and_shares, auth_shares))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_garbling::{BinaryGadgets, Fancy, FancyBinary, FancyReveal};
    use swanky_aes_rng::AesRng;
    use swanky_authenticated_bits::authshares::{PartyA, PartyB};
    use swanky_ot_alsz_kos::kos;

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
    ) -> Result<BinaryBundle<F::Item>, F::Error>
    where
        F: FancyReveal + Fancy + BinaryGadgets + FancyBinary,
    {
        f.bin_addition_no_carry(&garbler_wires, &evaluator_wires)
    }
    #[test]
    fn test_preprocessing_fancy_sum() {
        let mut rng = AesRng::new();
        let input_size = 400;
        let (_shares_gb, _shares_ev) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = AesRng::new();
                let mut generator_auth_share =
                    AuthShareGenerator::<Garbler, kos::Sender, kos::Receiver>::new(c, &mut rng)?;
                let mut generator_and_triples =
                    AndTripleGenerator::<Garbler, kos::Sender, kos::Receiver>::new(c, &mut rng)?;
                Ok(f_preprocessing(
                    fancy_sum,
                    &mut generator_and_triples,
                    &mut generator_auth_share,
                    input_size,
                    c,
                    &mut rng,
                ))
            },
            |c| {
                let mut rng = AesRng::new();
                let mut generator_auth_share =
                    AuthShareGenerator::<Evaluator, kos::Sender, kos::Receiver>::new(c, &mut rng)?;
                let mut generator_and_triples =
                    AndTripleGenerator::<Evaluator, kos::Sender, kos::Receiver>::new(c, &mut rng)?;
                Ok(f_preprocessing(
                    fancy_sum,
                    &mut generator_and_triples,
                    &mut generator_auth_share,
                    input_size,
                    c,
                    &mut rng,
                ))
            },
        )
        .unwrap();
    }
}

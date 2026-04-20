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
use std::collections::HashMap;

use fancy_garbling::BinaryBundle;
use rand::{CryptoRng, Rng};
use swanky_authenticated_bits::and_triples::AndTripleGenerator;
use swanky_channel::Channel;
use swanky_party::GenericParty;

pub mod wire;
use crate::preprocesser::wire::{IndexedWire, PreProcessedWire};
use crate::unifier::{CircuitExecutor, CircuitExecutorItem};

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
    circuit: &impl Fn(
        &mut CircuitExecutor<P, RNG>,
        BinaryBundle<CircuitExecutorItem<P>>,
        BinaryBundle<CircuitExecutorItem<P>>,
        &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<CircuitExecutorItem<P>>>,
    and_generator: &mut AndTripleGenerator<P>,
    input_size: usize,
    channel: &mut Channel,
    rng: &mut RNG,
) -> swanky_error::Result<(
    HashMap<usize, PreProcessedWire<P>>,
    HashMap<usize, PreProcessedWire<P>>,
)> {
    // First Analyze the circuit gates by simulating both parties
    let mut circuit_analyzer = CircuitExecutor::new_analyzer();
    circuit_analyzer.mock_circuit(&circuit, input_size, channel)?;

    let nands = circuit_analyzer.analyzer().nands();
    let ninputs = circuit_analyzer.analyzer().ninputs();
    let nconstants = circuit_analyzer.analyzer().nconstants();

    // Create as many random and triples as there are AND gates
    let mut rand_and_triples = Vec::with_capacity(nands);
    and_generator.generate(nands, &mut rand_and_triples, channel, rng)?;

    // Create as many authenticated shares as there are AND, Constant and Input gates.
    let mut auth_shares = Vec::with_capacity(nands + ninputs + nconstants);
    and_generator.auth_share_generator_mut().generate(
        nands + ninputs,
        &mut auth_shares,
        channel,
        rng,
    )?;
    let mut wire_preprocessor = CircuitExecutor::new_preprocessing_wires(auth_shares);
    wire_preprocessor.mock_circuit(&circuit, input_size, channel)?;

    let (left_wires, right_wires, indices) = wire_preprocessor.and_gate_input_shares();
    let mut known_triples_out = Vec::with_capacity(rand_and_triples.len());
    and_generator.to_known_triple(
        &rand_and_triples,
        &left_wires,
        &right_wires,
        &mut known_triples_out,
        channel,
    )?;

    let mut known_triple_map = HashMap::new();
    for (index, auth_share) in indices.iter().zip(known_triples_out) {
        let wire = PreProcessedWire::new(*index, auth_share);
        known_triple_map.insert(wire.to_index(), wire);
    }

    Ok((
        wire_preprocessor.into_indexed_auth_shares(),
        known_triple_map,
    ))
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
        let input_size = 500;
        let (_shares_gb, _shares_ev) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = SwankyRng::new();
                let mut generator_and_triples = AndTripleGenerator::<Garbler>::new(c, &mut rng)?;
                Ok(f_preprocessing(
                    &fancy_sum,
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
                    &fancy_sum,
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

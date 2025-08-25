//! Authenticated AND triples.
//!
//! An authenticated AND triple is a random authenticated triple $`(\langle x
//! \rangle, \langle y \rangle, \langle z \rangle)`$ [^1] such that $`x \cdot y
//! = z`$.
//!
//! # Details
//!
//! To generate [`AndTriple`]s, the parties first compute _leaky_ AND triples,
//! which are equivalent to [`AndTriple`]s with the exception that an
//! adversarial Party A can attempt to guess the value of $`x`$: if correct this
//! remains undetected, if incorrect the adversary is caught.
//!
//! We turn leaky AND triples into _authenticated_ AND triples using a bucketing
//! technique: the parties generate a bunch of leaky AND triples, randomly
//! shuffle these, and the "bucket" them into buckets of size $`B`$, where $`B`$
//! depends on the total number of authenticated AND triples desired. Each
//! bucket is them combined into a single (authenticated) AND triple. See Katz
//! et al. [^2] for details.
//!
//! # Security
//!
//! The generation protocol for leaky AND triples requires that the
//! least-significant bit of the $`\Delta`$ value be fixed, and hence the
//! protocol achieves at most 127-bits of security.
//!
//! In addition, the parameters for combining leaky AND triples into
//! authenticated AND triples assumes 40-bits of statistical security.
//!
//! [^1]: See [`crate::authshares`] for the definition of the $`\langle x
//! \rangle`$ notation.
//!
//! [^2]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing Authenticated
//! Garbling for Faster Secure Two-Party Computation".
//! <https://eprint.iacr.org/2018/578.pdf>

use crate::leaky_and_triples::{LeakyAndTriple, LeakyAndTripleGenerator};
use bytemuck::TransparentWrapper;
use rand::{CryptoRng, Rng, SeedableRng, seq::SliceRandom};
use swanky_adversary::Malicious;
use swanky_aes_rng::AesRng;
use swanky_channel::Channel;
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender};
use swanky_party::Party;
use vectoreyes::U8x16;

/// An AND triple.
///
/// See [`crate::and_triples`] for details. [`AndTriple`]s can be generated using
/// [`AndTripleGenerator`].
#[derive(Clone, Copy, TransparentWrapper)]
#[repr(transparent)]
pub struct AndTriple<P: Party>(
    // A `LeakyAndTriple` is still an AND triple.
    LeakyAndTriple<P>,
);

impl<P: Party> From<LeakyAndTriple<P>> for AndTriple<P> {
    fn from(value: LeakyAndTriple<P>) -> Self {
        Self(value)
    }
}

/// A type for generating [`AndTriple`]s.
pub struct AndTripleGenerator<P: Party, OTS: CorrelatedSender, OTR: CorrelatedReceiver> {
    leaky_generator: LeakyAndTripleGenerator<P, OTS, OTR>,
}

impl<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> AndTripleGenerator<P, OTS, OTR>
{
    /// Create a new [`AndTripleGenerator`].
    pub fn new<RNG: CryptoRng + Rng>(channel: &mut Channel, rng: RNG) -> eyre::Result<Self> {
        let leaky_generator = LeakyAndTripleGenerator::new(channel, rng)?;
        Ok(Self { leaky_generator })
    }

    /// Create a new [`AndTripleGenerator`] with a supplied $`\Delta`$ value.
    ///
    /// # Panics
    /// This panics if $`\mathsf{lsb}(\Delta_\mathsf{A}) \neq 1`$ or if
    /// $`\mathsf{lsb}(\Delta_\mathsf{B}) \neq 0`$.
    pub fn new_with_delta<RNG: CryptoRng + Rng>(
        delta: U8x16,
        channel: &mut Channel,
        rng: RNG,
    ) -> eyre::Result<Self> {
        let leaky_generator = LeakyAndTripleGenerator::new_with_delta(delta, channel, rng)?;
        Ok(Self { leaky_generator })
    }

    /// Generate a vector of AND triples.
    ///
    /// # Panics
    /// This panics if `ntriples < 320`, as 320 is the minimum number
    /// of ntriples that can be generated.
    pub fn generate<RNG: CryptoRng + Rng>(
        &mut self,
        ntriples: usize,
        out: &mut Vec<AndTriple<P>>,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> eyre::Result<()> {
        // See Table 4 from https://eprint.iacr.org/2017/030.pdf.
        //
        // These numbers are for a statistical security of 40 bits.
        let bucket_size = if ntriples >= 280000 {
            3
        } else if ntriples >= 3100 {
            4
        } else if ntriples >= 320 {
            5
        } else {
            panic!("Too few triples: Must be >= 320");
        };
        let nleaky = ntriples * bucket_size;
        let mut leaky_ands = Vec::with_capacity(nleaky);
        self.leaky_generator
            .generate(nleaky, &mut leaky_ands, channel, rng)?;
        // Run a coin-tossing protocol to determine a seed for permuting the
        // generated leaky AND triples.
        let seed = rng.r#gen::<U8x16>();
        let random = match P::WHICH {
            swanky_party::WhichParty::Prover(_) => swanky_cointoss::send(channel, &[seed])?[0],
            swanky_party::WhichParty::Verifier(_) => swanky_cointoss::receive(channel, &[seed])?[0],
        };
        // Do the permutation.
        let mut shuffle_rng = AesRng::from_seed(random);
        leaky_ands.shuffle(&mut shuffle_rng);
        // Bucket the leaky AND triples and combine them into (non-leaky) AND triples.
        for bucket in leaky_ands.chunks(bucket_size) {
            let triple = self.leaky_generator.combine(bucket, channel)?;
            out.push(triple.into());
        }
        Ok(())
    }

    /// Open the AND triples in `triples`.
    ///
    /// This corresponds to opening each of the underlying authenticated shares.
    pub fn open(&self, triples: &[AndTriple<P>], channel: &mut Channel) -> eyre::Result<()> {
        // An AND triple is _also_ a leaky-AND triple (with no leak), so use
        // that `open` method here.
        self.leaky_generator
            .open(AndTriple::peel_slice(triples), channel)
    }

    /// The $`\Delta`$ value used to validate the other party's shares.
    pub fn delta(&self) -> U8x16 {
        self.leaky_generator.delta()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authshares::{PartyA, PartyB};
    use proptest::prelude::*;
    use swanky_aes_rng::AesRng;
    use swanky_ot_alsz_kos::kos;

    fn generate(
        ntriples: usize,
        seed_prover: U8x16,
        seed_verifier: U8x16,
    ) -> (
        Vec<AndTriple<PartyA>>,
        Vec<AndTriple<PartyB>>,
        AndTripleGenerator<PartyA, kos::Sender, kos::Receiver>,
        AndTripleGenerator<PartyB, kos::Sender, kos::Receiver>,
    ) {
        let mut output_a: Vec<AndTriple<PartyA>> = vec![];
        let mut output_b: Vec<AndTriple<PartyB>> = vec![];
        let (generator_a, generator_b) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = AesRng::from_seed(seed_prover);
                let mut generator =
                    AndTripleGenerator::<PartyA, kos::Sender, kos::Receiver>::new(c, &mut rng)?;
                generator.generate(ntriples, &mut output_a, c, &mut rng)?;
                Ok(generator)
            },
            |c| {
                let mut rng = AesRng::from_seed(seed_verifier);
                let mut generator =
                    AndTripleGenerator::<PartyB, kos::Sender, kos::Receiver>::new(c, &mut rng)?;
                generator.generate(ntriples, &mut output_b, c, &mut rng)?;
                Ok(generator)
            },
        )
        .unwrap();
        (output_a, output_b, generator_a, generator_b)
    }

    fn validate(
        generator_a: &AndTripleGenerator<PartyA, kos::Sender, kos::Receiver>,
        generator_b: &AndTripleGenerator<PartyB, kos::Sender, kos::Receiver>,
        output_a: Vec<AndTriple<PartyA>>,
        output_b: Vec<AndTriple<PartyB>>,
    ) -> (bool, bool, U8x16, U8x16) {
        let ((validation_a, delta_a), (validation_b, delta_b)) =
            swanky_channel::local::local_channel_pair(
                |c| {
                    let result = generator_a.open(&output_a, c);
                    let delta = generator_a.delta();
                    Ok((result.is_ok(), delta))
                },
                |c| {
                    let result = generator_b.open(&output_b, c);
                    let delta = generator_b.delta();
                    Ok((result.is_ok(), delta))
                },
            )
            .unwrap();
        (validation_a, validation_b, delta_a, delta_b)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn honest_generation_works(ntriples in 320..1000usize,
                                   seed_prover in any::<u128>(),
                                   seed_verifier in any::<u128>()) {
            let (output_a, output_b, generator_a, generator_b) = generate(ntriples, seed_prover.into(), seed_verifier.into());
            let (validation_a, validation_b, _, _) =
                validate(&generator_a, &generator_b, output_a, output_b);
            prop_assert!(validation_a);
            prop_assert!(validation_b);
        }
    }
}

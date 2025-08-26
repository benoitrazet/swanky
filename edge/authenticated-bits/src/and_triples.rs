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

use crate::{
    authshares::{AuthShare, AuthShareGenerator},
    leaky_and_triples::{LeakyAndTriple, LeakyAndTripleGenerator},
};
use bytemuck::TransparentWrapper;
use rand::{CryptoRng, Rng, SeedableRng, seq::SliceRandom};
use swanky_adversary::Malicious;
use swanky_aes_rng::AesRng;
use swanky_channel::Channel;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender};
use swanky_party::{Party, WhichParty};
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

impl<P: Party> AndTriple<P> {
    /// The authenticated share $`\langle x \rangle`$.
    pub fn x(&self) -> AuthShare<P> {
        self.0.x()
    }

    /// The authenticated share $`\langle y \rangle`$.
    pub fn y(&self) -> AuthShare<P> {
        self.0.y()
    }

    /// The authenticated share $`\langle z \rangle`$ such that $`z = x \cdot
    /// y`$.
    pub fn z(&self) -> AuthShare<P> {
        self.0.z()
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

    /// Turn a random AND triple into a "known" AND triple.
    ///
    /// Given random AND triple $`(\langle x \rangle, \langle y \rangle, \langle
    /// z \rangle)`$ such that $`x \cdot y = z`$ and authenticated shares
    /// $`\langle a \rangle`$ and $`\langle b \rangle`$, output AND triple
    /// $`(\langle a \rangle, \langle b \rangle, \langle c \rangle`$ such that
    /// $`a \cdot b = c`$.
    pub fn to_known_triple(
        &self,
        random: &AndTriple<P>,
        a: &AuthShare<P>,
        b: &AuthShare<P>,
        channel: &mut Channel,
    ) -> eyre::Result<AuthShare<P>> {
        // We convert from a random triple to a known triple using a trick from
        // [1] (although at this point it's largely considered a "standard
        // technique"). The protocol works as follows. The random AND triple
        // `⟨x⟩, ⟨y⟩, ⟨z⟩` is used to "mask" the `⟨a⟩` and `⟨b⟩` shares so they
        // can be opened. These are then used to compute `⟨c⟩ := ⟨a b⟩`.
        //
        // In particular, the parties compute:
        // ```
        //     ⟨c⟩ := ⟨z⟩ ⊕ f ⟨y⟩ ⊕ g ⟨x⟩ ⊕ f g
        // ```
        // where `f := ⟨a⟩ ⊕ ⟨x⟩` and `g := ⟨b⟩ ⊕ ⟨y⟩` are opened between each
        // party. Note that the above formula can be expanded into:
        // ```
        //     ⟨z⟩ ⊕ (⟨a⟩ ⊕ ⟨x⟩) ⟨y⟩ ⊕ (⟨b⟩ ⊕ ⟨y⟩) ⟨x⟩ ⊕ (⟨a⟩ ⊕ ⟨x⟩) (⟨b⟩ ⊕ ⟨y⟩)
        // =>  ⟨z⟩ ⊕ ⟨a⟩⟨y⟩ ⊕ ⟨x⟩⟨y⟩ ⊕ ⟨b⟩⟨x⟩ ⊕ ⟨y⟩⟨x⟩ ⊕ ⟨a⟩⟨b⟩ ⊕ ⟨a⟩⟨y⟩ ⊕ ⟨x⟩⟨b⟩ ⊕ ⟨x⟩⟨y⟩
        // =>  ⟨a⟩⟨b⟩
        // ```
        // which is what we want.
        //
        // [1]: "Efficient multiparty protocols using circuit randomization." D.
        //     Beaver. CRYPTO 1991.

        // Compute openings of `f := ⟨a⟩ ⊕ ⟨x⟩` and `g := ⟨b⟩ ⊕ ⟨y⟩`.
        let f = *a ^ random.x();
        let g = *b ^ random.y();
        let (f, g) = match P::WHICH {
            WhichParty::Prover(_) => {
                channel.write(&f.bit())?;
                channel.write(&g.bit())?;
                let f2: F2 = channel.read()?;
                let g2: F2 = channel.read()?;
                let f = f.bit() + f2;
                let g = g.bit() + g2;
                (f, g)
            }
            WhichParty::Verifier(_) => {
                let f1: F2 = channel.read()?;
                let g1: F2 = channel.read()?;
                channel.write(&f.bit())?;
                channel.write(&g.bit())?;
                let f = f.bit() + f1;
                let g = g.bit() + g1;
                (f, g)
            }
        };
        // Compute `⟨c⟩ := ⟨z⟩ ⊕ f ⟨y⟩ ⊕ g ⟨x⟩ ⊕ f g`.
        let mut c = random.z();
        if f == F2::ONE {
            c = c ^ random.y();
        }
        if g == F2::ONE {
            c = c ^ random.x();
        }
        let c = self
            .leaky_generator
            .auth_share_generator
            .xor_with_const(c, f * g);
        Ok(c)
    }

    /// The $`\Delta`$ value used to validate the other party's shares.
    pub fn delta(&self) -> U8x16 {
        self.leaky_generator.delta()
    }

    /// Return the [`AuthShareGenerator`] associated with this generator.
    pub fn auth_share_generator(&self) -> &AuthShareGenerator<P, OTS, OTR> {
        &self.leaky_generator.auth_share_generator
    }

    /// Return the _mutable_ [`AuthShareGenerator`] associated with this generator.
    pub fn auth_share_generator_mut(&mut self) -> &mut AuthShareGenerator<P, OTS, OTR> {
        &mut self.leaky_generator.auth_share_generator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authshares::{PartyA, PartyB};
    use proptest::prelude::*;
    use swanky_aes_rng::AesRng;
    use swanky_ot_alsz_kos::kos;

    fn generators(
        mut rng_a: &mut AesRng,
        mut rng_b: &mut AesRng,
    ) -> (
        AndTripleGenerator<PartyA, kos::Sender, kos::Receiver>,
        AndTripleGenerator<PartyB, kos::Sender, kos::Receiver>,
    ) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let generator =
                    AndTripleGenerator::<PartyA, kos::Sender, kos::Receiver>::new(c, &mut rng_a)?;
                Ok(generator)
            },
            |c| {
                let generator =
                    AndTripleGenerator::<PartyB, kos::Sender, kos::Receiver>::new(c, &mut rng_b)?;
                Ok(generator)
            },
        )
        .unwrap()
    }

    fn generate_triples(
        ntriples: usize,
        generator_a: &mut AndTripleGenerator<PartyA, kos::Sender, kos::Receiver>,
        generator_b: &mut AndTripleGenerator<PartyB, kos::Sender, kos::Receiver>,
        mut rng_a: &mut AesRng,
        mut rng_b: &mut AesRng,
    ) -> (Vec<AndTriple<PartyA>>, Vec<AndTriple<PartyB>>) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut triples: Vec<AndTriple<PartyA>> = vec![];
                generator_a.generate(ntriples, &mut triples, c, &mut rng_a)?;
                Ok(triples)
            },
            |c| {
                let mut triples: Vec<AndTriple<PartyB>> = vec![];
                generator_b.generate(ntriples, &mut triples, c, &mut rng_b)?;
                Ok(triples)
            },
        )
        .unwrap()
    }

    fn generate_shares(
        nshares: usize,
        generator_a: &mut AndTripleGenerator<PartyA, kos::Sender, kos::Receiver>,
        generator_b: &mut AndTripleGenerator<PartyB, kos::Sender, kos::Receiver>,
        mut rng_a: &mut AesRng,
        mut rng_b: &mut AesRng,
    ) -> (Vec<AuthShare<PartyA>>, Vec<AuthShare<PartyB>>) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut shares: Vec<AuthShare<PartyA>> = vec![];
                generator_a.auth_share_generator_mut().generate(
                    nshares,
                    &mut shares,
                    c,
                    &mut rng_a,
                )?;
                Ok(shares)
            },
            |c| {
                let mut shares: Vec<AuthShare<PartyB>> = vec![];
                generator_b.auth_share_generator_mut().generate(
                    nshares,
                    &mut shares,
                    c,
                    &mut rng_b,
                )?;
                Ok(shares)
            },
        )
        .unwrap()
    }

    fn validate_triples(
        generator_a: &AndTripleGenerator<PartyA, kos::Sender, kos::Receiver>,
        generator_b: &AndTripleGenerator<PartyB, kos::Sender, kos::Receiver>,
        triples_a: Vec<AndTriple<PartyA>>,
        triples_b: Vec<AndTriple<PartyB>>,
    ) -> (bool, bool) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let result = generator_a.open(&triples_a, c);
                Ok(result.is_ok())
            },
            |c| {
                let result = generator_b.open(&triples_b, c);
                Ok(result.is_ok())
            },
        )
        .unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn honest_generation_works(ntriples in 320..1000usize,
                                   seed_a in any::<u128>(),
                                   seed_b in any::<u128>()) {
            let mut rng_a = AesRng::from_seed(seed_a.into());
            let mut rng_b = AesRng::from_seed(seed_b.into());
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (triples_a, triples_b) = generate_triples(ntriples, &mut generator_a, &mut generator_b, &mut rng_a, &mut rng_b);
            let (validation_a, validation_b) =
                validate_triples(&generator_a, &generator_b, triples_a, triples_b);
            prop_assert!(validation_a);
            prop_assert!(validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn fixing_and_triples_works(ntriples in 320..1000usize,
                                    seed_a in any::<u128>(),
                                    seed_b in any::<u128>()) {
            let mut rng_a = AesRng::from_seed(seed_a.into());
            let mut rng_b = AesRng::from_seed(seed_b.into());
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (triples_a, triples_b) = generate_triples(
                ntriples,
                &mut generator_a,
                &mut generator_b,
                &mut rng_a,
                &mut rng_b,
            );
            let (shares_a, shares_b) = generate_shares(
                ntriples * 2,
                &mut generator_a,
                &mut generator_b,
                &mut rng_a,
                &mut rng_b,
            );
            // Convert the random triples to known triples.
            let mut cs_a = vec![];
            let mut cs_b = vec![];
            swanky_channel::local::local_channel_pair(
                |channel| {
                    for (triple, shares) in triples_a.iter().zip(shares_a.chunks_exact(2)) {
                        let c = generator_a.to_known_triple(triple, &shares[0], &shares[1], channel)?;
                        cs_a.push(c);
                    }
                    Ok(())
                },
                |channel| {
                    for (triple, shares) in triples_b.iter().zip(shares_b.chunks_exact(2)) {
                        let c = generator_b.to_known_triple(triple, &shares[0], &shares[1], channel)?;
                        cs_b.push(c);
                    }
                    Ok(())
                },
            )
            .unwrap();
            // Open the shares and triples to check validity.
            let ((shares_a, cs_a), (shares_b, cs_b)) = swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut shares: Vec<F2> = vec![];
                    let mut cs: Vec<F2> = vec![];
                    generator_a
                        .auth_share_generator()
                        .open(&shares_a, &mut shares, channel)?;
                    generator_a
                        .auth_share_generator()
                        .open(&cs_a, &mut cs, channel)?;
                    Ok((shares, cs))
                },
                |channel| {
                    let mut shares: Vec<F2> = vec![];
                    let mut cs: Vec<F2> = vec![];
                    generator_b
                        .auth_share_generator()
                        .open(&shares_b, &mut shares, channel)?;
                    generator_b
                        .auth_share_generator()
                        .open(&cs_b, &mut cs, channel)?;
                    Ok((shares, cs))
                },
            )
            .unwrap();
            // Check validity of all the triples.
            for i in 0..ntriples {
                // `auth_share_generator().open()` should ensure that the opened
                // shares are the same.
                assert_eq!(shares_a[2 * i], shares_b[2 * i]);
                assert_eq!(shares_a[2 * i + 1], shares_b[2 * i + 1]);
                assert_eq!(cs_a[i], cs_b[i]);
                let a = shares_a[2 * i];
                let b = shares_a[2 * i + 1];
                let c = cs_a[i];
                assert_eq!(a * b, c);
            }
        }
    }
}

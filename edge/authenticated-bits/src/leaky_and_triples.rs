//! Leaky AND triples.
//!
//! An AND triple is a random authenticated AND triple $`(\langle x \rangle,
//! \langle y \rangle, \langle z \rangle)`$ [1] such that $`x \cdot y = z`$. A
//! _leaky_ AND triple is an AND triple where the adversary can guess the value
//! of $`x`$: if correct this remains undetected, of incorrect the adversary is
//! caught.
//!
//! [1] See [`crate::authshares`] for the definition of the $`\langle x
//! \rangle`$ notation.

use crate::authshares::{AuthShare, AuthShareGenerator};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use swanky_adversary::Malicious;
use swanky_aes_hash::CorrelationRobustHash;
use swanky_channel::Channel;
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer, F128b};
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender};
use swanky_party::{Party, WhichParty};
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};
use vectoreyes::{SimdBase, U8x16};

/// A leaky AND triple.
///
/// See [`crate::leaky_and_triples`] for details.
#[derive(Clone, Copy)]
pub struct LeakyAndTriple<P: Party> {
    /// The authenticated share $`\langle x \rangle`$.
    x: AuthShare<P>,
    /// The authenticated share $`\langle y \rangle`$.
    y: AuthShare<P>,
    /// The authenticated share $`\langle z \rangle`$ such that $`z = x \cdot
    /// y`$.
    z: AuthShare<P>,
}

/// A type for generating [`LeakyAndTriple`]s.
pub struct LeakyAndTripleGenerator<P: Party, OTS: CorrelatedSender, OTR: CorrelatedReceiver> {
    auth_share_generator: AuthShareGenerator<P, OTS, OTR>,
}

impl<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> LeakyAndTripleGenerator<P, OTS, OTR>
{
    /// Create a new [`LeakyAndTripleGenerator`].
    pub fn new<RNG: CryptoRng + Rng>(channel: &mut Channel, mut rng: RNG) -> eyre::Result<Self> {
        let delta = rng.r#gen::<F128b>();
        // We require that for Party A (the Prover) `lsb(Δ) = 1`, and for Party
        // B (the Verifier) `lsb(Δ) = 0`. So adjust `delta` as needed.
        let delta = match P::WHICH {
            WhichParty::Prover(_) => {
                if lsb(delta) == F2::ZERO {
                    delta + F128b::ONE
                } else {
                    delta
                }
            }
            WhichParty::Verifier(_) => {
                if lsb(delta) == F2::ONE {
                    delta + F128b::ONE
                } else {
                    delta
                }
            }
        };
        Self::new_with_delta(U8x16::from(delta), channel, rng)
    }

    /// Create a new [`LeakyAndTripleGenerator`] with a supplied $`\Delta`$
    /// value.
    ///
    /// # Panics
    /// This panics if $`\mathsf{lsb}(\Delta_\mathsf{A}) \neq 1`$ or if
    /// $`\mathsf{lsb}(\Delta_\mathsf{B}) \neq 0`$.
    pub fn new_with_delta<RNG: CryptoRng + Rng>(
        delta: U8x16,
        channel: &mut Channel,
        rng: RNG,
    ) -> eyre::Result<Self> {
        match P::WHICH {
            WhichParty::Prover(_) => {
                assert_eq!(lsb(F128b::from(delta)), F2::ONE)
            }
            WhichParty::Verifier(_) => {
                assert_eq!(lsb(F128b::from(delta)), F2::ZERO)
            }
        }
        let auth_share_generator = AuthShareGenerator::new_with_delta(delta, channel, rng)?;
        Ok(Self {
            auth_share_generator,
        })
    }

    /// Generate a vector of leaky AND triples.
    ///
    /// This implements the $`\Pi_{\mathsf{Land}}`$ protocol (Figure 5) from [1].
    ///
    /// [1] J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing
    /// Authenticated Garbling for Faster Secure Two-Party Computation".
    /// https://eprint.iacr.org/2018/578.pdf
    pub fn generate<RNG: CryptoRng + Rng>(
        &mut self,
        ntriples: usize,
        out: &mut Vec<LeakyAndTriple<P>>,
        channel: &mut Channel,
        rng: RNG,
    ) -> eyre::Result<()> {
        let nshares = 3 * ntriples;
        let delta = F128b::from(self.auth_share_generator.delta());
        let mut shares = Vec::with_capacity(nshares);

        // Step 1.
        // A and B obtain random authenticated shares (⟨x₁ | x₂⟩, ⟨y₁ | y₂⟩, ⟨z₁ | r⟩).
        self.auth_share_generator
            .generate(nshares, &mut shares, channel, rng)?;
        let cs: Vec<F128b> = shares
            .iter()
            .tuples()
            .map(|(_, y, _)|
            // A and B locally compute `y Δ + K[y] + M[y]`.
            y.bit() * delta + F128b::from(y.key()) + F128b::from(y.mac()))
            .collect();

        // Step 2.
        let mut es = Vec::with_capacity(ntriples);
        // Send `G := H(K[x] + Δ) + H(K[x]) + C`.
        let send_g = |x: &AuthShare<P>, c: &F128b, channel: &mut Channel| -> eyre::Result<()> {
            let g = hash(F128b::from(x.key()) + delta) + hash(F128b::from(x.key())) + c;
            channel.write(&g)?;
            Ok(())
        };
        // Receive `G` and compute `E := x G + H(M[x]) + x C`.
        let mut receive_g_and_compute_e =
            |x: &AuthShare<P>, c: &F128b, channel: &mut Channel| -> eyre::Result<()> {
                let g = channel.read::<F128b>()?;
                let e = x.bit() * g + hash(F128b::from(x.mac())) + x.bit() * *c;
                es.push(e);
                Ok(())
            };
        for ((x, _, _), c) in shares.iter().tuples().zip(cs.iter()) {
            match P::WHICH {
                WhichParty::Prover(_) => {
                    // A sends `G₁ := H(K[x] + Δ) + H(K[x]) + C` to B.
                    send_g(x, c, channel)?;
                }
                WhichParty::Verifier(_) => {
                    // B computes `E₁ := x G₁ + H(M[x]) + x C`.
                    receive_g_and_compute_e(x, c, channel)?;
                }
            }
        }
        // Step 3.
        for ((x, _, _), c) in shares.iter().tuples().zip(cs.iter()) {
            match P::WHICH {
                WhichParty::Verifier(_) => {
                    // B sends `G₂ := H(K[x] + Δ) + H(K[x]) + C` to A.
                    send_g(x, c, channel)?;
                }
                WhichParty::Prover(_) => {
                    // A computes `E₂ := x G₂ + H(M[x]) + x C`.
                    receive_g_and_compute_e(x, c, channel)?;
                }
            }
        }

        // Step 4.
        let ss: Vec<F128b> = shares
            .iter()
            .tuples()
            .zip(es)
            .map(|((x, _, z), e)| {
                // Compute `S := H(K[x]) + E + (z Δ + K[z] + M[z])`.
                hash(F128b::from(x.key()))
                    + e
                    + (z.bit() * delta + F128b::from(z.key()) + F128b::from(z.mac()))
            })
            .collect();

        let mut ds = Vec::with_capacity(ntriples);
        // Sends the LSBs of `ss` to the other party.
        let send_lsb = |channel: &mut Channel| -> eyre::Result<()> {
            let mut serializer: F2BitSerializer =
                SequenceSerializer::new(&mut channel.as_std_io())?;
            for s in ss.iter() {
                let lsb_s_mine = lsb(*s);
                serializer.write(channel.as_std_io(), lsb_s_mine)?;
            }
            serializer.finish(channel.as_std_io())?;
            Ok(())
        };
        // Receives the LSBs of `ss` from the other party.
        let mut receive_lsb = |channel: &mut Channel| -> eyre::Result<()> {
            let mut deserializer: F2BitDeserializer =
                SequenceDeserializer::new(&mut channel.as_std_io())?;
            for s in ss.iter() {
                let lsb_s_mine = lsb(*s);
                let lsb_s_other = deserializer.read(channel.as_std_io())?;
                let d = lsb_s_mine + lsb_s_other;
                ds.push(d);
            }
            Ok(())
        };
        match P::WHICH {
            WhichParty::Prover(_) => {
                // A sends `lsb(S₁)` to B.
                send_lsb(channel)?;
                // A receives `lsb(S₂)` from B and computes `d := lsb(S₁) +
                // lsb(S₂)`.
                receive_lsb(channel)?;
            }
            WhichParty::Verifier(_) => {
                // B receives `lsb(S₁)` from A.
                receive_lsb(channel)?;
                // B sends `lsb(S₂)` to A and computes `d := lsb(S₁) + lsb(S₂)`.
                send_lsb(channel)?;
            }
        }
        for (((x, y, z), _s), d) in shares.into_iter().tuples().zip(ss).zip(ds) {
            // 🦺 SECURITY TODO 🦺: send stuff to `Feq`.
            let z_new = self.auth_share_generator.xor_with_const(z, d);
            let triple = LeakyAndTriple { x, y, z: z_new };
            out.push(triple)
        }
        Ok(())
    }

    /// Open the (leaky) AND triples in `triples`.
    ///
    /// This corresponds to opening each of the underlying authenticated shares.
    pub fn open(&self, triples: &[LeakyAndTriple<P>], channel: &mut Channel) -> eyre::Result<()> {
        let (xs, ys, zs): (Vec<_>, Vec<_>, Vec<_>) = triples
            .iter()
            .map(|triple| (triple.x, triple.y, triple.z))
            .multiunzip();
        let mut output_x = Vec::with_capacity(triples.len());
        self.auth_share_generator
            .open(&xs, &mut output_x, channel)?;
        let mut output_y = Vec::with_capacity(triples.len());
        self.auth_share_generator
            .open(&ys, &mut output_y, channel)?;
        let mut output_z = Vec::with_capacity(triples.len());
        self.auth_share_generator
            .open(&zs, &mut output_z, channel)?;
        // Confirm when testing that all the triples are indeed valid.
        #[cfg(test)]
        {
            for (i, ((x, y), z)) in output_x
                .iter()
                .zip(output_y.iter())
                .zip(output_z.iter())
                .enumerate()
            {
                assert_eq!(x * y, *z, "Iteration {i} failed");
            }
        }
        Ok(())
    }

    /// Combine a "bucket" of [`LeakyAndTriple`]s to produce a single
    /// [`AndTriple`].
    ///
    /// This implements the $`\Pi_{\mathsf{aAND}}`$ protocol (Figure 9) from
    /// [1].
    ///
    /// # Security
    /// This assumes that the bucket is of the correct size. The bucket size
    /// depends on the number of (non-leaky) AND triples to be created:
    ///
    /// | ≤ # Triples | Bucket Size |
    /// | :---------: | :---------: |
    /// |         320 |           5 |
    /// |       3,100 |           4 |
    /// |     280,000 |           3 |
    ///
    /// That is, if you want to create `N` triples, you need to generate `B · N`
    /// leaky-AND triples---where `B` is the bucket size---randomly permute the
    /// triples, and then call `combine` on buckets of size `B`.
    ///
    /// This implies that _there is no security guarantee_ when generating more
    /// than 280,000 triples!
    ///
    /// # Panics
    /// This panics if `bucket` is empty.
    ///
    /// [1] X. Wang, S. Ranellucci, J. Katz. "Authenticated Garbling and
    /// Efficient Maliciously Secure Two-Party Computation".
    /// https://eprint.iacr.org/2017/030.pdf
    pub fn combine(
        &mut self,
        bucket: &[LeakyAndTriple<P>],
        channel: &mut Channel,
    ) -> eyre::Result<LeakyAndTriple<P>> {
        assert!(!bucket.is_empty());
        bucket
            .iter()
            .skip(1)
            .try_fold(*bucket.first().unwrap(), |acc, triple| {
                // Compute `⟨d⟩ := ⟨y⟩ ⊕ ⟨y'⟩` and open `⟨d⟩`.
                let d = acc.y ^ triple.y;
                let mut d_vector = Vec::with_capacity(1);
                self.auth_share_generator
                    .open(&[d], &mut d_vector, channel)?;
                // Compute the resulting triple as:
                //   ⟨x''⟩ := ⟨x⟩ ⊕ ⟨x'⟩
                //   ⟨y''⟩ := ⟨y⟩
                //   ⟨z''⟩ := ⟨z⟩ ⊕ ⟨z'⟩ ⊕ d ⟨x'⟩
                Ok(LeakyAndTriple {
                    x: acc.x ^ triple.x,
                    y: acc.y,
                    z: if d_vector[0] == F2::ONE {
                        acc.z ^ triple.z ^ triple.x
                    } else {
                        acc.z ^ triple.z
                    },
                })
            })
    }

    /// The $`\Delta`$ value used to validate the other party's shares.
    pub fn delta(&self) -> U8x16 {
        self.auth_share_generator.delta()
    }
}

fn hash(input: F128b) -> F128b {
    // 🦺 SECURITY TODO 🦺: confirm that a correlation-robust hash is sufficient here.
    F128b::from(CorrelationRobustHash::fixed_key().hash(U8x16::from(input)))
}

// Extract the least-significant bit from a `F128b` value.
fn lsb(input: F128b) -> F2 {
    F2::from((U8x16::from(input).extract::<0>() & 1) != 0)
}

#[cfg(test)]
mod tests {
    use crate::authshares::{PartyA, PartyB};

    use super::*;
    use proptest::prelude::*;
    use swanky_aes_rng::AesRng;
    use swanky_ot_alsz_kos::kos;

    fn generate(
        ntriples: usize,
    ) -> (
        Vec<LeakyAndTriple<PartyA>>,
        Vec<LeakyAndTriple<PartyB>>,
        LeakyAndTripleGenerator<PartyA, kos::Sender, kos::Receiver>,
        LeakyAndTripleGenerator<PartyB, kos::Sender, kos::Receiver>,
    ) {
        let mut output_a: Vec<LeakyAndTriple<PartyA>> = vec![];
        let mut output_b: Vec<LeakyAndTriple<PartyB>> = vec![];
        let (generator_a, generator_b) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = AesRng::new();
                let mut generator =
                    LeakyAndTripleGenerator::<PartyA, kos::Sender, kos::Receiver>::new(
                        c, &mut rng,
                    )?;
                generator.generate(ntriples, &mut output_a, c, &mut rng)?;
                Ok(generator)
            },
            |c| {
                let mut rng = AesRng::new();
                let mut generator =
                    LeakyAndTripleGenerator::<PartyB, kos::Sender, kos::Receiver>::new(
                        c, &mut rng,
                    )?;
                generator.generate(ntriples, &mut output_b, c, &mut rng)?;
                Ok(generator)
            },
        )
        .unwrap();
        (output_a, output_b, generator_a, generator_b)
    }

    fn validate(
        generator_a: &LeakyAndTripleGenerator<PartyA, kos::Sender, kos::Receiver>,
        generator_b: &LeakyAndTripleGenerator<PartyB, kos::Sender, kos::Receiver>,
        output_a: Vec<LeakyAndTriple<PartyA>>,
        output_b: Vec<LeakyAndTriple<PartyB>>,
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

    #[test]
    fn honest_generation_works() {
        let ntriples = 10000;
        let (output_a, output_b, generator_a, generator_b) = generate(ntriples);
        let (validation_a, validation_b, _, _) =
            validate(&generator_a, &generator_b, output_a, output_b);
        assert!(validation_a);
        assert!(validation_b);
    }

    #[test]
    fn combine_works() {
        let ntriples = 320 * 5;
        let (output_a, output_b, mut generator_a, mut generator_b) = generate(ntriples);
        swanky_channel::local::local_channel_pair(
            |channel| {
                for bucket in output_a.chunks(5) {
                    let triple = generator_a.combine(bucket, channel).unwrap();
                    let result = generator_a.open(&[triple], channel);
                    assert!(result.is_ok());
                }
                Ok(())
            },
            |channel| {
                for bucket in output_b.chunks(5) {
                    let triple = generator_b.combine(bucket, channel).unwrap();
                    let result = generator_b.open(&[triple], channel);
                    assert!(result.is_ok());
                }
                Ok(())
            },
        )
        .unwrap();
    }

    proptest! {
        #[test]
        fn lsb_works(input in any::<u128>()) {
            assert_eq!(lsb(F128b::from(U8x16::from(input))), F2::from((input & 1) != 0));
        }
    }
}

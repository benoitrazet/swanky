//! Bit Authentication from CorrelatedOT
#![deny(missing_docs)]
use eyre;
use ocelot::ot::{CorrelatedReceiver, CorrelatedSender};
use rand::{CryptoRng, Rng};
use scuttlebutt::Malicious;
use swanky_channel::Channel;
use swanky_party::{
    Party, WhichParty,
    either::PartyEither,
    either::PartyEitherCopy,
    private::{ProverPrivate, ProverPrivateCopy, VerifierPrivateCopy},
};
use vectoreyes::U8x16;
/// The Prover's part of the authentication bit
///
/// The Prover holds a bit that they wish to
/// authenticate and receive a MAC which corresponds
/// to that authentication.
#[derive(Debug, Default, Clone, Copy)]
struct ProverAuthBit {
    /// Mac authenticating the bit
    mac: U8x16,
    /// Bit value
    bit: bool,
}
/// The Verifier's part of the authentication bit
///
/// The Verifier holds a local `key` per bit
/// that authenticates the bit and verifies the
/// integrity of the provers MAC.
#[derive(Debug, Default, Clone, Copy)]
struct VerifierAuthBit {
    /// Key from OT
    key: U8x16,
}
/// A type that represents the Party's part of the authenticated bit
pub struct AuthBit<P: Party>(PartyEitherCopy<P, ProverAuthBit, VerifierAuthBit>);

impl<P: Party> AuthBit<P> {
    /// Return the [ProverAuthBit] component.
    fn to_prover(&self) -> ProverPrivateCopy<P, ProverAuthBit> {
        self.0.into_privates().0
    }
    /// Return the [VerifierAuthBit] component.
    fn to_verifier(&self) -> VerifierPrivateCopy<P, VerifierAuthBit> {
        self.0.into_privates().1
    }
    /// Output the verifier's key associated with this [AuthBit].
    pub fn key(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.to_verifier().map(|vab| vab.key)
    }
    /// Output the prover's MAC associated with this [AuthBit].
    pub fn mac(&self) -> ProverPrivateCopy<P, U8x16> {
        self.to_prover().map(|vab| vab.mac)
    }
    /// Output the prover's bit associated with this [AuthBit].
    pub fn bit(&self) -> ProverPrivateCopy<P, bool> {
        self.to_prover().map(|vab| vab.bit)
    }
}

/// XOR two authenticated bits. Linear operations on authenticated bits are "free"
/// (i.e. can be done locally).
impl<P: Party> std::ops::BitXor for AuthBit<P> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let pairs = self.0.zip(rhs.0);
        AuthBit(pairs.map(
            |(lhs, rhs)| ProverAuthBit {
                mac: lhs.mac ^ rhs.mac,
                bit: lhs.bit ^ rhs.bit,
            },
            |(lhs, rhs)| VerifierAuthBit {
                key: lhs.key ^ rhs.key,
            },
        ))
    }
}
/// A struct which contains multiple generated authentication bit
///
/// When `P = Verifier`, this struct also stores the verifier's
/// global key `delta`.
pub struct AuthBitGenerator<P: Party, OTS: CorrelatedSender, OTR: CorrelatedReceiver> {
    /// A vector of authenticated bit.
    data: Vec<AuthBit<P>>,
    /// The verifier's global key.
    delta: VerifierPrivateCopy<P, U8x16>,
    /// The party's OT
    ot: PartyEither<P, OTR, OTS>,
}

/// A struct which contains multiple generated authentication bit
impl<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> AuthBitGenerator<P, OTS, OTR>
{
    /// Create a new [AuthBitGenerator] based on the type of
    /// the party. In the case of the `P = Verifier`, store the
    /// `delta` value.
    pub fn new<RNG>(
        delta: VerifierPrivateCopy<P, U8x16>,
        mut channel: &mut Channel,
        mut rng: RNG,
    ) -> Self
    where
        RNG: CryptoRng + Rng,
    {
        AuthBitGenerator {
            data: vec![],
            delta: delta,
            ot: match P::WHICH {
                WhichParty::Prover(ev_pr) => {
                    PartyEither::prover_new(ev_pr, OTR::init(&mut channel, &mut rng).unwrap())
                }
                WhichParty::Verifier(ev_vr) => {
                    PartyEither::verifier_new(ev_vr, OTS::init(&mut channel, &mut rng).unwrap())
                }
            },
        }
    }
    /// Generate `count` authenticated bits. These are stored in `output`.
    ///
    /// TODO: Possibly allow the user to specify the bits they would like
    /// authenticated instead of always generate them at random
    pub fn generate<RNG>(
        &mut self,
        mut channel: &mut Channel,
        count: usize,
        bits_in: Option<ProverPrivate<P, Vec<bool>>>,
        mut rng: RNG,
    ) -> eyre::Result<()>
    where
        RNG: CryptoRng + Rng,
    {
        match P::WHICH {
            WhichParty::Prover(ev_pr) => {
                let bits = if bits_in.is_some() {
                    bits_in.unwrap().into_inner(ev_pr)
                } else {
                    (0..count).map(|_| rng.r#gen::<bool>()).collect()
                };
                let macs = self.ot.as_mut().prover_into(ev_pr).receive_correlated(
                    &mut channel,
                    &bits,
                    &mut rng,
                )?;

                self.data
                    .extend(bits.into_iter().zip(macs).map(|(bit, mac)| {
                        AuthBit(PartyEitherCopy::prover_new(
                            ev_pr,
                            ProverAuthBit { bit: bit, mac: mac },
                        ))
                    }));
                Ok(())
            }
            WhichParty::Verifier(ev_vr) => {
                let delta = self.delta().into_inner(ev_vr);
                let keys = self.ot.as_mut().verifier_into(ev_vr).send_correlated(
                    &mut channel,
                    &vec![delta; count],
                    &mut rng,
                )?;
                self.data.extend(keys.into_iter().map(|(ot_0, _ot_1)| {
                    AuthBit(PartyEitherCopy::verifier_new(
                        ev_vr,
                        VerifierAuthBit { key: ot_0 },
                    ))
                }));

                Ok(())
            }
        }
    }
    /// "Open" a all authenticated bits.
    ///
    /// This corresponds to the prover sending $(b, M)$ to the verifier, who checks
    /// that $K = M xor b Delta$.
    pub fn open(&self, channel: &mut Channel) -> eyre::Result<VerifierPrivateCopy<P, bool>> {
        match P::WHICH {
            WhichParty::Prover(ev_pr) => {
                for ab in self.data.iter() {
                    // TODO: Change how bits are sent, this is extremely inefficent
                    channel.write_bytes(&[ab.bit().into_inner(ev_pr) as u8])?;
                    // TODO: Potentially leave last bit in the mac for the
                    // authenticated bit.
                    channel.write_bytes(ab.mac().into_inner(ev_pr).as_ref())?;
                }
                Ok(VerifierPrivateCopy::empty(ev_pr))
            }
            WhichParty::Verifier(ev_vr) => {
                let mut validation = true;
                for ab in self.data.iter() {
                    let mut bit_bytes = [0u8; 1];
                    channel.read_bytes(&mut bit_bytes)?;
                    let mut mac_bytes = [0u8; 16];
                    channel.read_bytes(&mut mac_bytes)?;
                    let mac = U8x16::from(mac_bytes);

                    validation &= mac
                        == if bit_bytes[0] == 1 {
                            ab.key().into_inner(ev_vr) ^ self.delta().into_inner(ev_vr)
                        } else {
                            ab.key().into_inner(ev_vr)
                        };
                }
                Ok(VerifierPrivateCopy::new(validation))
            }
        }
    }
    /// "Output the verifier's Δ value."
    pub fn delta(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthBitGenerator;
    use ocelot::ot;
    use swanky_aes_rng::AesRng;
    use swanky_channel::Channel;
    use swanky_party::{
        IS_PROVER, IS_VERIFIER, Prover, Verifier, either::PartyEitherCopy,
        private::VerifierPrivateCopy,
    };
    fn authenticate_in_clear(
        pr: &[AuthBit<Prover>],
        vr: &[AuthBit<Verifier>],
        delta: U8x16,
    ) -> bool {
        pr.iter()
            .zip(vr)
            .map(|(ab_pr, ab_vr)| {
                ab_pr.mac().into_inner(IS_PROVER)
                    == (if ab_pr.bit().into_inner(IS_PROVER) {
                        ab_vr.key().into_inner(IS_VERIFIER) ^ delta
                    } else {
                        ab_vr.key().into_inner(IS_VERIFIER)
                    })
            })
            .reduce(|b1, b2| b1 && b2)
            .unwrap()
    }
    fn run_authentication(
        bits_in: Option<Vec<bool>>,
        count: usize,
    ) -> (Vec<AuthBit<Prover>>, Vec<AuthBit<Verifier>>, bool, U8x16) {
        let mut output_pr: Vec<AuthBit<Prover>> = vec![];
        let mut output_vr: Vec<AuthBit<Verifier>> = vec![];
        let (_, (validation, delta)) = swanky_channel::local::local_channel_pair(
            |channel_pr| {
                let mut rng = AesRng::new();
                let bits = if bits_in.is_some() {
                    Some(ProverPrivate::new(bits_in.unwrap()))
                } else {
                    None
                };
                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(
                        VerifierPrivateCopy::empty(IS_PROVER),
                        channel_pr,
                        &mut rng,
                    );
                let _ = auth_bits.generate::<&mut AesRng>(channel_pr, count, bits, &mut rng);
                let _ = auth_bits.open(channel_pr);
                output_pr = auth_bits.data;

                Ok(())
            },
            |channel_vr| {
                let mut rng = AesRng::new();
                let delta = rng.r#gen::<U8x16>();
                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(
                        VerifierPrivateCopy::new(delta),
                        channel_vr,
                        &mut rng,
                    );
                let _ = auth_bits.generate::<&mut AesRng>(channel_vr, count, None, &mut rng);
                let validation = auth_bits.open(channel_vr).unwrap().into_inner(IS_VERIFIER);
                output_vr = auth_bits.data;
                Ok((validation, delta))
            },
        )
        .unwrap();
        (output_pr, output_vr, validation, delta)
    }
    // proptest! {
    #[test]
    // Turn this into a proptest
    fn test_correct_generation() {
        let count = 10;
        let (output_pr, output_vr, validation, delta) = run_authentication(None, count);

        let validation_clear = authenticate_in_clear(&output_pr, &output_vr, delta);
        assert!(validation);
        assert_eq!(validation, validation_clear);
    }
    #[test]
    fn test_bit_true() {
        let count = 1;
        let bits = vec![true];
        let (output_pr, output_vr, _validation, delta) = run_authentication(Some(bits), count);
        assert!(
            output_pr[0].mac().into_inner(IS_PROVER)
                == (output_vr[0].key().into_inner(IS_VERIFIER) ^ delta)
        )
    }
    #[test]
    fn test_bit_false() {
        let count = 1;
        let bits = vec![false];
        let (output_pr, output_vr, _validation, _delta) = run_authentication(Some(bits), count);
        assert!(
            output_pr[0].mac().into_inner(IS_PROVER) == output_vr[0].key().into_inner(IS_VERIFIER)
        )
    }
    #[test]
    // Turn this into a proptest
    fn test_failing_tamper_mac() {
        let count = 10;
        let (_, res) = swanky_channel::local::local_channel_pair(
            |channel_pr| {
                let mut rng = AesRng::new();
                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(
                        VerifierPrivateCopy::empty(IS_PROVER),
                        channel_pr,
                        &mut rng,
                    );
                let _ = auth_bits.generate::<&mut AesRng>(channel_pr, count, None, &mut rng);
                // Mess with the mac
                auth_bits.data[0] = AuthBit(PartyEitherCopy::prover_new(
                    IS_PROVER,
                    ProverAuthBit {
                        bit: auth_bits.data[0].bit().into_inner(IS_PROVER),
                        mac: rng.r#gen(),
                    },
                ));

                let _ = auth_bits.open(channel_pr);

                Ok(())
            },
            |channel_vr| {
                let mut rng = AesRng::new();
                let delta = rng.r#gen::<U8x16>();
                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(
                        VerifierPrivateCopy::new(delta),
                        channel_vr,
                        &mut rng,
                    );
                let _ = auth_bits.generate::<&mut AesRng>(channel_vr, count, None, &mut rng);
                Ok(auth_bits.open(channel_vr).unwrap().into_inner(IS_VERIFIER))
            },
        )
        .unwrap();
        assert!(res == false);
    }
    // }
}

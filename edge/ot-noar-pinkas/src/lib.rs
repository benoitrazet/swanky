#![deny(missing_docs)]
//! Implementation of the Naor-Pinkas oblivious transfer protocol (cf.
//! <https://dl.acm.org/citation.cfm?id=365502>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use swanky_adversary::SemiHonest;
use swanky_block::Block;
use swanky_channel_legacy::AbstractChannel;
use swanky_ocelot_error::Error;
use swanky_ot_traits::{Receiver as OtReceiver, Sender as OtSender};

pub(crate) fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> Block {
    let h = blake3::keyed_hash(pt.compress().as_bytes(), &tweak.to_le_bytes());
    Block::from(<[u8; 16]>::try_from(&h.as_bytes()[0..16]).unwrap())
}

/// Oblivious transfer sender.
pub struct Sender {}
/// Oblivious transfer receiver.
pub struct Receiver {}

impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        _: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        mut rng: &mut RNG,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let mut cs = Vec::with_capacity(m);
        let mut pks = Vec::with_capacity(m);
        for _ in 0..m {
            let c = RistrettoPoint::random(&mut rng);
            channel.write_pt(&c)?;
            cs.push(c);
        }
        channel.flush()?;
        for c in cs.into_iter() {
            let pk0 = channel.read_pt()?;
            pks.push((pk0, c - pk0));
        }
        for (i, (input, pk)) in inputs.iter().zip(pks).enumerate() {
            let r = Scalar::random(&mut rng);
            let ei0 = &r * RISTRETTO_BASEPOINT_TABLE;
            let h = hash_pt(i as u128, &(pk.0 * r));
            let e01 = h ^ input.0;
            let h = hash_pt(i as u128, &(pk.1 * r));
            let e11 = h ^ input.1;
            channel.write_pt(&ei0)?;
            channel.write_block(&e01)?;
            channel.write_block(&e11)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Naor-Pinkas Sender")
    }
}

impl OtReceiver for Receiver {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        _: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {})
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let m = inputs.len();
        let mut cs = Vec::with_capacity(m);
        let mut ks = Vec::with_capacity(m);
        for _ in 0..m {
            let c = channel.read_pt()?;
            cs.push(c);
        }
        for (b, c) in inputs.iter().zip(cs) {
            let k = Scalar::random(&mut rng);
            let pk = &k * RISTRETTO_BASEPOINT_TABLE;
            let pk_ = c - pk;
            match b {
                false => channel.write_pt(&pk)?,
                true => channel.write_pt(&pk_)?,
            };
            ks.push(k);
        }
        channel.flush()?;
        inputs
            .iter()
            .zip(ks)
            .enumerate()
            .map(|(i, (b, k))| {
                let ei0 = channel.read_pt()?;
                let e01 = channel.read_block()?;
                let e11 = channel.read_block()?;
                let e1 = match b {
                    false => e01,
                    true => e11,
                };
                let h = hash_pt(i as u128, &(ei0 * k));
                Ok(h ^ e1)
            })
            .collect()
    }
}

impl std::fmt::Display for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Naor-Pinkas Receiver")
    }
}

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

#[test]
fn test_functionality() {
    swanky_ot_test::test_otext::<Sender, Receiver>(128);
}

//! Oblivious transfer traits + instantiations.
//!
//! This module provides traits for standard oblivious transfer (OT), correlated
//! OT, and random OT, alongside implementations of the following OT protocols:
//!
//! * `dummy`: a dummy and completely insecure OT for testing purposes.
//! * `naor_pinkas`: Naor-Pinkas semi-honest OT.
//! * `chou_orlandi`: Chou-Orlandi malicious OT.
//! * `alsz`: Asharov-Lindell-Schneider-Zohner semi-honest OT extension (+ correlated and random OT).
//! * `kos`: Keller-Orsini-Scholl malicious OT extension (+ correlated and random OT).
//!

pub mod alsz;
pub mod chou_orlandi;
pub mod dummy;
pub mod explicit_round;
pub mod kos;
pub mod kos_delta;
pub mod naor_pinkas;

use curve25519_dalek::RistrettoPoint;
use swanky_block::Block;

pub(crate) fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> Block {
    let h = blake3::keyed_hash(pt.compress().as_bytes(), &tweak.to_le_bytes());
    Block::from(<[u8; 16]>::try_from(&h.as_bytes()[0..16]).unwrap())
}

pub use swanky_ot_traits::*;
/// Instantiation of the Chou-Orlandi OT sender.
pub type ChouOrlandiSender = chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub type ChouOrlandiReceiver = chou_orlandi::Receiver;
/// Instantiation of the dummy OT sender.
pub type DummySender = dummy::Sender;
/// Instantiation of the dummy OT receiver.
pub type DummyReceiver = dummy::Receiver;
/// Instantiation of the Naor-Pinkas OT sender.
pub type NaorPinkasSender = naor_pinkas::Sender;
/// Instantiation of the Naor-Pinkas OT receiver.
pub type NaorPinkasReceiver = naor_pinkas::Receiver;
/// Instantiation of the ALSZ OT extension sender, using Chou-Orlandi as the base OT.
pub type AlszSender = alsz::Sender<ChouOrlandiReceiver>;
/// Instantiation of the ALSZ OT extension receiver, using Chou-Orlandi as the base OT.
pub type AlszReceiver = alsz::Receiver<ChouOrlandiSender>;
/// Instantiation of the KOS OT extension sender, using Chou-Orlandi as the base OT.
pub type KosSender = kos::Sender<ChouOrlandiReceiver>;
/// Instantiation of the KOS OT extension receiver, using Chou-Orlandi as the base OT.
pub type KosReceiver = kos::Receiver<ChouOrlandiSender>;
/// Instantiation of the KOS Delta-OT extension sender, using Chou-Orlandi as the base OT.
pub type KosDeltaSender = kos_delta::Sender<ChouOrlandiReceiver>;
/// Instantiation of the KOS Delta-OT extension receiver, using Chou-Orlandi as the base OT.
pub type KosDeltaReceiver = kos_delta::Receiver<ChouOrlandiSender>;

use crate::{
    FancyBinary,
    fancy::{
        HasModulus,
        bundle::{Bundle, BundleGadgets},
    },
    util,
};
use itertools::Itertools;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use swanky_channel::Channel;

/// Bundle which is explicitly binary representation.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BinaryBundle<W>(Bundle<W>);

impl<W: Clone + HasModulus> BinaryBundle<W> {
    /// Create a new binary bundle from a vector of wires.
    pub fn new(ws: Vec<W>) -> BinaryBundle<W> {
        BinaryBundle(Bundle::new(ws))
    }
}

impl<W: Clone + HasModulus> Deref for BinaryBundle<W> {
    type Target = Bundle<W>;

    fn deref(&self) -> &Bundle<W> {
        &self.0
    }
}

impl<W: Clone + HasModulus> DerefMut for BinaryBundle<W> {
    fn deref_mut(&mut self) -> &mut Bundle<W> {
        &mut self.0
    }
}

impl<W: Clone + HasModulus> From<Bundle<W>> for BinaryBundle<W> {
    fn from(b: Bundle<W>) -> BinaryBundle<W> {
        debug_assert!(b.moduli().iter().all(|&p| p == 2));
        BinaryBundle(b)
    }
}

impl<F: FancyBinary> BinaryGadgets for F {}

/// Extension trait for `Fancy` providing gadgets that operate over bundles of mod2 wires.
pub trait BinaryGadgets: FancyBinary + BundleGadgets {
    /// Encode a binary input bundle.
    fn bin_encode(
        &mut self,
        value: u128,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        let xs = util::u128_to_bits(value, nbits);
        self.encode_bundle(&xs, &vec![2; nbits], channel)
            .map(BinaryBundle::from)
    }

    /// Receive an binary input bundle.
    fn bin_receive(
        &mut self,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        self.receive_bundle(&vec![2; nbits], channel)
            .map(BinaryBundle::from)
    }

    /// Encode many binary input bundles.
    fn bin_encode_many(
        &mut self,
        values: &[u128],
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<BinaryBundle<Self::Item>>> {
        let xs = values
            .iter()
            .flat_map(|x| util::u128_to_bits(*x, nbits))
            .collect_vec();
        let mut wires = self.encode_many(&xs, &vec![2; values.len() * nbits], channel)?;
        let buns = (0..values.len())
            .map(|_| {
                let ws = wires.drain(0..nbits).collect_vec();
                BinaryBundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Receive many binary input bundles.
    fn bin_receive_many(
        &mut self,
        ninputs: usize,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<BinaryBundle<Self::Item>>> {
        let mut wires = self.receive_many(&vec![2; ninputs * nbits], channel)?;
        let buns = (0..ninputs)
            .map(|_| {
                let ws = wires.drain(0..nbits).collect_vec();
                BinaryBundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Output a binary bundle and interpret the result as a `u128`.
    fn bin_output(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u128>> {
        Ok(self
            .output_bundle(x, channel)?
            .map(|bs| util::u128_from_bits(&bs)))
    }

    /// Output a slice of binary bundles and interpret the results as a `u128`.
    fn bin_outputs(
        &mut self,
        xs: &[BinaryBundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u128>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.bin_output(x, channel)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }
}

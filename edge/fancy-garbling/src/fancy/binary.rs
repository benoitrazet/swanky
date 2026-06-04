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

    /// Extract the underlying bundle from this binary bundle.
    pub fn extract(self) -> Bundle<W> {
        self.0
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

    /// Demux a binary bundle into a unary vector.
    ///
    /// # Panics
    /// Panics if the length of `x` is greater than eight.
    fn bin_demux(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let wires = x.wires();
        let nbits = wires.len();
        assert!(nbits <= 8, "wire bitlength is too large");

        let mut outs = Vec::with_capacity(1 << nbits);

        for ix in 0..1 << nbits {
            let mut acc = wires[0].clone();
            if (ix & 1) == 0 {
                acc = self.negate(&acc);
            }
            for (i, w) in wires.iter().enumerate().skip(1) {
                if ((ix >> i) & 1) > 0 {
                    acc = self.and(&acc, w, channel)?;
                } else {
                    let not_w = self.negate(w);
                    acc = self.and(&acc, &not_w, channel)?;
                }
            }
            outs.push(acc);
        }

        Ok(outs)
    }

    /// arithmetic right shift (shifts the sign of the MSB into the new spaces)
    fn bin_rsa(&mut self, x: &BinaryBundle<Self::Item>, c: usize) -> BinaryBundle<Self::Item> {
        self.bin_shr(x, c, x.wires().last().unwrap())
    }

    /// logical right shift (shifts 0 into the empty spaces)
    fn bin_rsl(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        c: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        let zero = self.constant(0, 2, channel)?;
        Ok(self.bin_shr(x, c, &zero))
    }

    /// shift a value right by a constant, filling space on the right by `pad`
    fn bin_shr(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        c: usize,
        pad: &Self::Item,
    ) -> BinaryBundle<Self::Item> {
        let mut wires: Vec<Self::Item> = Vec::with_capacity(x.wires().len());

        for i in 0..x.wires().len() {
            let src_idx = i + c;
            if src_idx >= x.wires().len() {
                wires.push(pad.clone())
            } else {
                wires.push(x.wires()[src_idx].clone())
            }
        }

        BinaryBundle::new(wires)
    }
}

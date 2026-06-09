use crate::{Fancy, FancyArithmetic, HasModulus};
use itertools::Itertools;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use swanky_channel::Channel;

/// A collection of wires, useful for the garbled gadgets defined by `BundleGadgets`.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Bundle<W>(Vec<W>);

impl<W: Clone + HasModulus> Bundle<W> {
    /// Create a new bundle from some wires.
    pub fn new(ws: Vec<W>) -> Bundle<W> {
        Bundle(ws)
    }

    /// Return the moduli of all the wires in the bundle.
    pub(crate) fn moduli(&self) -> Vec<u16> {
        self.0.iter().map(HasModulus::modulus).collect()
    }

    /// Extract the wires from this bundle.
    pub fn wires(&self) -> &Vec<W> {
        &self.0
    }

    /// Get the number of wires in this bundle.
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Returns a new bundle only containing wires with matching moduli.
    pub(crate) fn with_moduli(&self, moduli: &[u16]) -> Bundle<W> {
        let old_ws = self.wires();
        let mut new_ws = Vec::with_capacity(moduli.len());
        for &p in moduli {
            if let Some(w) = old_ws.iter().find(|&x| x.modulus() == p) {
                new_ws.push(w.clone());
            } else {
                panic!("Bundle::with_moduli: no {} modulus in bundle", p);
            }
        }
        Bundle(new_ws)
    }

    /// Pad the Bundle with val, n times.
    pub(crate) fn pad(&mut self, val: &W, n: usize) {
        for _ in 0..n {
            self.0.push(val.clone());
        }
    }

    /// Insert a wire from the Bundle
    pub(crate) fn insert(&mut self, wire_index: usize, val: W) {
        self.0.insert(wire_index, val)
    }

    /// push a wire onto the Bundle.
    pub(crate) fn push(&mut self, val: W) {
        self.0.push(val);
    }

    /// Pop a wire from the Bundle.
    pub(crate) fn pop(&mut self) -> Option<W> {
        self.0.pop()
    }

    /// Access the underlying iterator
    pub fn iter(&self) -> std::slice::Iter<'_, W> {
        self.0.iter()
    }

    /// Reverse the wires
    pub(crate) fn reverse(&mut self) {
        self.0.reverse();
    }
}

impl<F: Fancy> BundleGadgets for F {}
impl<F: FancyArithmetic> ArithmeticBundleGadgets for F {}

/// Arithmetic operations on wire bundles, extending the capability of `FancyArithmetic` operating
/// on individual wires.
pub trait ArithmeticBundleGadgets: FancyArithmetic {
    /// If b=0 then return 0, else return x.
    fn mask(
        &mut self,
        b: &Self::Item,
        x: &Bundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Bundle<Self::Item>> {
        x.wires()
            .iter()
            .map(|xwire| self.mul(xwire, b, channel))
            .collect::<swanky_error::Result<_>>()
            .map(Bundle)
    }
}

/// Extension trait for Fancy which provides Bundle constructions which are not
/// necessarily CRT nor binary-based.
pub trait BundleGadgets: Fancy {
    /// Encode a bundle.
    fn encode_bundle(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Bundle<Self::Item>> {
        self.encode_many(values, moduli, channel).map(Bundle::new)
    }

    /// Receive a bundle.
    fn receive_bundle(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Bundle<Self::Item>> {
        self.receive_many(moduli, channel).map(Bundle::new)
    }

    /// Encode many input bundles.
    ///
    /// # Panics,
    /// Panics if `values` and `moduli` are of unequal length.
    fn encode_bundles(
        &mut self,
        values: &[Vec<u16>],
        moduli: &[Vec<u16>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Bundle<Self::Item>>> {
        let qs = moduli.iter().flatten().cloned().collect_vec();
        let xs = values.iter().flatten().cloned().collect_vec();
        assert_eq!(xs.len(), qs.len(), "unequal number of values and moduli");
        let mut wires = self.encode_many(&xs, &qs, channel)?;
        let buns = moduli
            .iter()
            .map(|qs| {
                let ws = wires.drain(0..qs.len()).collect_vec();
                Bundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Receive many input bundles.
    fn receive_many_bundles(
        &mut self,
        moduli: &[Vec<u16>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Bundle<Self::Item>>> {
        let qs = moduli.iter().flatten().cloned().collect_vec();
        let mut wires = self.receive_many(&qs, channel)?;
        let buns = moduli
            .iter()
            .map(|qs| {
                let ws = wires.drain(0..qs.len()).collect_vec();
                Bundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Creates a bundle of constant wires using moduli `ps`.
    fn constant_bundle(
        &mut self,
        xs: &[u16],
        ps: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Bundle<Self::Item>> {
        xs.iter()
            .zip(ps.iter())
            .map(|(&x, &p)| self.constant(x, p, channel))
            .collect::<swanky_error::Result<_>>()
            .map(Bundle)
    }

    /// Output the wires that make up a bundle.
    fn output_bundle(
        &mut self,
        x: &Bundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u16>>> {
        let ws = x.wires();
        let mut outputs = Vec::with_capacity(ws.len());
        for w in ws.iter() {
            outputs.push(self.output(w, channel)?);
        }
        Ok(outputs.into_iter().collect())
    }

    /// Output a slice of bundles.
    fn output_bundles(
        &mut self,
        xs: &[Bundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<Vec<u16>>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.output_bundle(x, channel)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }
}

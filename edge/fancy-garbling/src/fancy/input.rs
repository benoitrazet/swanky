use super::*;
use crate::util;
use itertools::Itertools;

/// Convenience functions for encoding input to Fancy objects.
pub trait FancyInput {
    /// The type that this Fancy object operates over.
    type Item: Clone + HasModulus;

    ////////////////////////////////////////////////////////////////////////////////
    // required methods

    /// Encode many values where the actual input is known.
    ///
    /// When writing a garbler, the return value must correspond to the zero
    /// wire label.
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>>;

    /// Receive many values where the input is not known.
    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>>;

    ////////////////////////////////////////////////////////////////////////////////
    // optional methods

    /// Encode a single value.
    ///
    /// When writing a garbler, the return value must correspond to the zero
    /// wire label.
    fn encode(
        &mut self,
        value: u16,
        modulus: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let mut xs = self.encode_many(&[value], &[modulus], channel)?;
        Ok(xs.remove(0))
    }

    /// Receive a single value.
    fn receive(&mut self, modulus: u16, channel: &mut Channel) -> swanky_error::Result<Self::Item> {
        let mut xs = self.receive_many(&[modulus], channel)?;
        Ok(xs.remove(0))
    }

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

    /// Encode a CRT input bundle.
    fn crt_encode(
        &mut self,
        value: u128,
        modulus: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<CrtBundle<Self::Item>> {
        let qs = util::factor(modulus);
        let xs = util::crt(value, &qs);
        self.encode_bundle(&xs, &qs, channel).map(CrtBundle::from)
    }

    /// Receive an CRT input bundle.
    fn crt_receive(
        &mut self,
        modulus: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<CrtBundle<Self::Item>> {
        let qs = util::factor(modulus);
        self.receive_bundle(&qs, channel).map(CrtBundle::from)
    }

    /// Encode many CRT input bundles.
    fn crt_encode_many(
        &mut self,
        values: &[u128],
        modulus: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<CrtBundle<Self::Item>>> {
        let mods = util::factor(modulus);
        let nmods = mods.len();
        let xs = values
            .iter()
            .flat_map(|x| util::crt(*x, &mods))
            .collect_vec();
        let qs = itertools::repeat_n(mods, values.len())
            .flatten()
            .collect_vec();
        let mut wires = self.encode_many(&xs, &qs, channel)?;
        let buns = (0..values.len())
            .map(|_| {
                let ws = wires.drain(0..nmods).collect_vec();
                CrtBundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Receive many CRT input bundles.
    fn crt_receive_many(
        &mut self,
        n: usize,
        modulus: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<CrtBundle<Self::Item>>> {
        let mods = util::factor(modulus);
        let nmods = mods.len();
        let qs = itertools::repeat_n(mods, n).flatten().collect_vec();
        let mut wires = self.receive_many(&qs, channel)?;
        let buns = (0..n)
            .map(|_| {
                let ws = wires.drain(0..nmods).collect_vec();
                CrtBundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

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
}

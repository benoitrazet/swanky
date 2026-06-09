use crate::{Fancy, FancyArithmetic, FancyProj, HasModulus};
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
impl<F: FancyArithmetic + FancyProj> ArithmeticProjBundleGadgets for F {}

/// Arithmetic operations on wire bundles, extending the capability of `FancyArithmetic` operating
/// on individual wires.
pub trait ArithmeticBundleGadgets: FancyArithmetic {
    /// Subtract two wire bundles, residue by residue.
    ///
    /// In CRT this is plain subtraction. In binary this is `xor`.
    ///
    /// # Panics
    /// Panics if `x` and `y` are not of the same length.
    fn sub_bundles(
        &mut self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Bundle<Self::Item> {
        assert_eq!(
            x.wires().len(),
            y.wires().len(),
            "`x` and `y` must be the same length"
        );
        Bundle::new(
            x.wires()
                .iter()
                .zip(y.wires().iter())
                .map(|(x, y)| self.sub(x, y))
                .collect::<Vec<Self::Item>>(),
        )
    }

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

/// Arithmetic operations on wire bundles that utilize projection gates.
pub trait ArithmeticProjBundleGadgets: FancyArithmetic + FancyProj {
    /// Mixed radix addition.
    ///
    /// # Panics
    /// Panics if `xs` is empty, or the moduli in `xs` are not all equal.
    fn mixed_radix_addition(
        &mut self,
        xs: &[Bundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Bundle<Self::Item>> {
        assert!(!xs.is_empty(), "`xs` cannot be empty");
        assert!(xs.iter().all(|x| x.moduli() == xs[0].moduli()));

        let nargs = xs.len();
        let n = xs[0].wires().len();

        let mut digit_carry = None;
        let mut carry_carry = None;
        let mut max_carry = 0;

        let mut res = Vec::with_capacity(n);

        for i in 0..n {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x.wires()[i].clone()).collect_vec();

            // compute the digit -- easy
            let digit_sum = self.add_many(&ds);
            let digit = digit_carry.map_or(digit_sum.clone(), |d| self.add(&digit_sum, &d));

            if i < n - 1 {
                // compute the carries
                let q = xs[0].wires()[i].modulus();
                // max_carry currently contains the max carry from the previous iteration
                let max_val = nargs as u16 * (q - 1) + max_carry;
                // now it is the max carry of this iteration
                max_carry = max_val / q;

                let modded_ds = ds
                    .iter()
                    .map(|d| self.mod_change(d, max_val + 1, channel))
                    .collect::<swanky_error::Result<Vec<Self::Item>>>()?;

                let carry_sum = self.add_many(&modded_ds);
                // add in the carry from the previous iteration
                let carry = carry_carry.map_or(carry_sum.clone(), |c| self.add(&carry_sum, &c));

                // carry now contains the carry information, we just have to project it to
                // the correct moduli for the next iteration
                let next_mod = xs[0].wires()[i + 1].modulus();
                let tt = (0..=max_val).map(|i| (i / q) % next_mod).collect_vec();
                digit_carry = Some(self.proj(&carry, next_mod, Some(tt), channel)?);

                let next_max_val = nargs as u16 * (next_mod - 1) + max_carry;

                if i < n - 2 {
                    if max_carry < next_mod {
                        carry_carry = Some(self.mod_change(
                            digit_carry.as_ref().unwrap(),
                            next_max_val + 1,
                            channel,
                        )?);
                    } else {
                        let tt = (0..=max_val).map(|i| i / q).collect_vec();
                        carry_carry =
                            Some(self.proj(&carry, next_max_val + 1, Some(tt), channel)?);
                    }
                } else {
                    // next digit is MSB so we dont need carry_carry
                    carry_carry = None;
                }
            } else {
                digit_carry = None;
                carry_carry = None;
            }
            res.push(digit);
        }
        Ok(Bundle(res))
    }

    /// Mixed radix addition only returning the MSB.
    ///
    /// # Panics
    /// Panics if `xs` is empty, or the moduli in `xs` are not all equal.
    fn mixed_radix_addition_msb_only(
        &mut self,
        xs: &[Bundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        assert!(!xs.is_empty(), "`xs` cannot be empty");
        assert!(xs.iter().all(|x| x.moduli() == xs[0].moduli()));

        let nargs = xs.len();
        let n = xs[0].wires().len();

        let mut opt_carry = None;
        let mut max_carry = 0;

        for i in 0..n - 1 {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x.wires()[i].clone()).collect_vec();
            // compute the carry
            let q = xs[0].moduli()[i];
            // max_carry currently contains the max carry from the previous iteration
            let max_val = nargs as u16 * (q - 1) + max_carry;
            // now it is the max carry of this iteration
            max_carry = max_val / q;

            // mod change the digits to the max sum possible plus the max carry of the
            // previous iteration
            let modded_ds = ds
                .iter()
                .map(|d| self.mod_change(d, max_val + 1, channel))
                .collect::<swanky_error::Result<Vec<Self::Item>>>()?;
            // add them up
            let sum = self.add_many(&modded_ds);
            // add in the carry
            let sum_with_carry = opt_carry
                .as_ref()
                .map_or(sum.clone(), |c| self.add(&sum, c));

            // carry now contains the carry information, we just have to project it to
            // the correct moduli for the next iteration. It will either be used to
            // compute the next carry, if i < n-2, or it will be used to compute the
            // output MSB, in which case it should be the modulus of the SB
            let next_mod = if i < n - 2 {
                nargs as u16 * (xs[0].moduli()[i + 1] - 1) + max_carry + 1
            } else {
                xs[0].moduli()[i + 1] // we will be adding the carry to the MSB
            };

            let tt = (0..=max_val).map(|i| (i / q) % next_mod).collect_vec();
            opt_carry = Some(self.proj(&sum_with_carry, next_mod, Some(tt), channel)?);
        }

        // compute the msb
        let ds = xs.iter().map(|x| x.wires()[n - 1].clone()).collect_vec();
        let digit_sum = self.add_many(&ds);
        Ok(opt_carry
            .as_ref()
            .map_or(digit_sum.clone(), |d| self.add(&digit_sum, d)))
    }

    /// Compute `x == y`. Returns a wire encoding the result mod 2.
    ///
    /// # Panics
    /// Panics if `x` and `y` do not have equal moduli.
    fn eq_bundles(
        &mut self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        assert_eq!(x.moduli(), y.moduli());

        let wlen = x.wires().len() as u16;
        let zs = x
            .wires()
            .iter()
            .zip_eq(y.wires().iter())
            .map(|(x, y)| {
                // compute (x-y == 0) for each residue
                let z = self.sub(x, y);
                let mut eq_zero_tab = vec![0; x.modulus() as usize];
                eq_zero_tab[0] = 1;
                self.proj(&z, wlen + 1, Some(eq_zero_tab), channel)
            })
            .collect::<swanky_error::Result<Vec<Self::Item>>>()?;
        // add up the results, and output whether they equal zero or not, mod 2
        let z = self.add_many(&zs);
        let b = zs.len();
        let mut tab = vec![0; b + 1];
        tab[b] = 1;
        self.proj(&z, 2, Some(tab), channel)
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

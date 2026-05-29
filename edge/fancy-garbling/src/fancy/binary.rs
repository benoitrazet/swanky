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

    /// Create a constant bundle using base 2 inputs.
    fn bin_constant_bundle(
        &mut self,
        val: u128,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        self.constant_bundle(&util::u128_to_bits(val, nbits), &vec![2; nbits], channel)
            .map(BinaryBundle)
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

    /// Xor the bits of two bundles together pairwise.
    fn bin_xor(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
    ) -> BinaryBundle<Self::Item> {
        BinaryBundle::new(
            x.wires()
                .iter()
                .zip(y.wires().iter())
                .map(|(x, y)| self.xor(x, y))
                .collect::<Vec<Self::Item>>(),
        )
    }

    /// And the bits of two bundles together pairwise.
    fn bin_and(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.and(x, y, channel))
            .collect::<swanky_error::Result<Vec<Self::Item>>>()
            .map(BinaryBundle::new)
    }

    /// Or the bits of two bundles together pairwise.
    fn bin_or(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.or(x, y, channel))
            .collect::<swanky_error::Result<Vec<Self::Item>>>()
            .map(BinaryBundle::new)
    }

    /// Binary addition. Returns the result and the carry.
    ///
    /// # Panics
    /// This panics if `xs` and `ys` do not have equal moduli.
    fn bin_addition(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<(BinaryBundle<Self::Item>, Self::Item)> {
        assert_eq!(xs.moduli(), ys.moduli());
        let xwires = xs.wires();
        let ywires = ys.wires();
        let (mut z, mut c) = self.adder(&xwires[0], &ywires[0], None, channel)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() {
            let res = self.adder(&xwires[i], &ywires[i], Some(&c), channel)?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        Ok((BinaryBundle::new(bs), c))
    }

    /// Binary addition. Avoids creating extra gates for the final carry.
    ///
    /// # Panics
    /// This panics if `xs` and `ys` do not have equal moduli.
    fn bin_addition_no_carry(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        assert_eq!(xs.moduli(), ys.moduli());
        let xwires = xs.wires();
        let ywires = ys.wires();
        let (mut z, mut c) = self.adder(&xwires[0], &ywires[0], None, channel)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() - 1 {
            let res = self.adder(&xwires[i], &ywires[i], Some(&c), channel)?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        // xor instead of add
        z = self.xor_many(&[
            xwires.last().unwrap().clone(),
            ywires.last().unwrap().clone(),
            c,
        ]);
        bs.push(z);
        Ok(BinaryBundle::new(bs))
    }

    /// Binary multiplication.
    ///
    /// Returns the lower-order half of the output bits, ie a number with the same number
    /// of bits as the inputs.
    ///
    /// # Panics
    /// This panics if `xs` and `ys` do not have equal moduli.
    fn bin_multiplication_lower_half(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        assert_eq!(xs.moduli(), ys.moduli());

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| self.and(x, &ywires[0], channel))
            .collect::<swanky_error::Result<Vec<Self::Item>>>()
            .map(BinaryBundle::new)?;

        for (i, ywire) in ywires.iter().enumerate().take(xwires.len()).skip(1) {
            let mul = xwires
                .iter()
                .map(|x| self.and(x, ywire, channel))
                .collect::<swanky_error::Result<Vec<Self::Item>>>()
                .map(BinaryBundle::new)?;
            let shifted = self.shift(&mul, i, channel).map(BinaryBundle)?;
            sum = self.bin_addition_no_carry(&sum, &shifted, channel)?;
        }

        Ok(sum)
    }

    /// Full multiplier.
    ///
    /// # Panics
    /// This panics if `xs` and `ys` do not have equal moduli.
    fn bin_mul(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        assert_eq!(xs.moduli(), ys.moduli());

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| self.and(x, &ywires[0], channel))
            .collect::<Result<_, _>>()
            .map(BinaryBundle::new)?;

        let zero = self.constant(0, 2, channel)?;
        sum.pad(&zero, 1);

        for (i, ywire) in ywires.iter().enumerate().take(xwires.len()).skip(1) {
            let mul = xwires
                .iter()
                .map(|x| self.and(x, ywire, channel))
                .collect::<Result<_, _>>()
                .map(BinaryBundle::new)?;
            let shifted = self
                .shift_extend(&mul, i, channel)
                .map(BinaryBundle::from)?;
            let res = self.bin_addition(&sum, &shifted, channel)?;
            sum = res.0;
            sum.push(res.1);
        }

        Ok(sum)
    }

    /// Divider.
    ///
    /// # Panics
    /// This panics if `xs` and `ys` do not have equal moduli.
    fn bin_div(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        assert_eq!(xs.moduli(), ys.moduli());
        let ys_neg = self.bin_twos_complement(ys, channel)?;
        let mut acc = self.bin_constant_bundle(0, xs.size(), channel)?;
        let mut qs = BinaryBundle::new(Vec::new());
        for x in xs.iter().rev() {
            acc.pop();
            acc.insert(0, x.clone());
            let (res, cout) = self.bin_addition(&acc, &ys_neg, channel)?;
            acc = self.bin_multiplex(&cout, &acc, &res, channel)?;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }

    /// Compute the twos complement of the input bundle (which must be base 2).
    fn bin_twos_complement(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        let not_xs = BinaryBundle::new(
            xs.wires()
                .iter()
                .map(|x| self.negate(x))
                .collect::<Vec<_>>(),
        );
        let one = self.bin_constant_bundle(1, xs.size(), channel)?;
        self.bin_addition_no_carry(&not_xs, &one, channel)
    }

    /// Subtract two binary bundles. Returns the result and whether it underflowed.
    ///
    /// Due to the way that `twos_complement(0) = 0`, underflow indicates `y != 0 && x >= y`.
    fn bin_subtraction(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<(BinaryBundle<Self::Item>, Self::Item)> {
        let neg_ys = self.bin_twos_complement(ys, channel)?;
        self.bin_addition(xs, &neg_ys, channel)
    }

    /// If `x=0` return `c1` as a bundle of constant bits, else return `c2`.
    fn bin_multiplex_constant_bits(
        &mut self,
        x: &Self::Item,
        c1: u128,
        c2: u128,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        let c1_bs = util::u128_to_bits(c1, nbits)
            .into_iter()
            .map(|x: u16| x > 0)
            .collect_vec();
        let c2_bs = util::u128_to_bits(c2, nbits)
            .into_iter()
            .map(|x: u16| x > 0)
            .collect_vec();
        c1_bs
            .into_iter()
            .zip(c2_bs)
            .map(|(b1, b2)| self.mux_constant_bits(x, b1, b2, channel))
            .collect::<swanky_error::Result<Vec<Self::Item>>>()
            .map(BinaryBundle::new)
    }

    /// Multiplex gadget for binary bundles
    fn bin_multiplex(
        &mut self,
        b: &Self::Item,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(xwire, ywire)| self.mux(b, xwire, ywire, channel))
            .collect::<swanky_error::Result<Vec<Self::Item>>>()
            .map(BinaryBundle::new)
    }

    /// Write the constant in binary and that gives you the shift amounts, Eg.. 7x is 4x+2x+x.
    fn bin_cmul(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        c: u128,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        let zero = self.bin_constant_bundle(0, nbits, channel)?;
        util::u128_to_bits(c, nbits)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b > 0 { Some(i) } else { None })
            .try_fold(zero, |z, shift_amt| {
                let s = self.shift(x, shift_amt, channel).map(BinaryBundle)?;
                self.bin_addition_no_carry(&z, &s, channel)
            })
    }

    /// Compute the absolute value of a binary bundle.
    fn bin_abs(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        let sign = x.wires().last().unwrap();
        let negated = self.bin_twos_complement(x, channel)?;
        self.bin_multiplex(sign, x, &negated, channel)
    }

    /// Returns 1 if `x < y` (signed version)
    fn bin_lt_signed(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // determine whether x and y are positive or negative
        let x_neg = &x.wires().last().unwrap();
        let y_neg = &y.wires().last().unwrap();
        let x_pos = self.negate(x_neg);
        let y_pos = self.negate(y_neg);

        // broken into cases based on x and y being negative or positive
        // base case: if x and y have the same sign - use unsigned lt
        let x_lt_y_unsigned = self.bin_lt(x, y, channel)?;

        // if x is negative and y is positive then x < y
        let tru = self.constant(1, 2, channel)?;
        let x_neg_y_pos = self.and(x_neg, &y_pos, channel)?;
        let r2 = self.mux(&x_neg_y_pos, &x_lt_y_unsigned, &tru, channel)?;

        // if x is positive and y is negative then !(x < y)
        let fls = self.constant(0, 2, channel)?;
        let x_pos_y_neg = self.and(&x_pos, y_neg, channel)?;
        self.mux(&x_pos_y_neg, &r2, &fls, channel)
    }

    /// Returns 1 if `x < y`.
    fn bin_lt(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // underflow indicates y != 0 && x >= y
        // requiring special care to remove the y != 0, which is what follows.
        let (_, lhs) = self.bin_subtraction(x, y, channel)?;

        // Now we build a clause equal to (y == 0 || x >= y), which we can OR with
        // lhs to remove the y==0 aspect.
        // check if y==0
        let y_contains_1 = self.or_many(y.wires(), channel)?;
        let y_eq_0 = self.negate(&y_contains_1);

        // if x != 0, then x >= y, ... assuming x is not negative
        let x_contains_1 = self.or_many(x.wires(), channel)?;

        // y == 0 && x >= y
        let rhs = self.and(&y_eq_0, &x_contains_1, channel)?;

        // (y != 0 && x >= y) || (y == 0 && x >= y)
        // => x >= y && (y != 0 || y == 0)\
        // => x >= y && 1
        // => x >= y
        let geq = self.or(&lhs, &rhs, channel)?;
        let ngeq = self.negate(&geq);

        let xy_neq_0 = self.or(&y_contains_1, &x_contains_1, channel)?;
        self.and(&xy_neq_0, &ngeq, channel)
    }

    /// Compute the maximum bundle in `xs`.
    ///
    /// # Panics
    /// Panics if `xs` is empty.
    fn bin_max(
        &mut self,
        xs: &[BinaryBundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        assert!(!xs.is_empty(), "`xs` cannot be empty");
        xs.iter().skip(1).try_fold(xs[0].clone(), |x, y| {
            let pos = self.bin_lt(&x, y, channel)?;
            let neg = self.negate(&pos);
            Ok(BinaryBundle::new(
                x.wires()
                    .iter()
                    .zip(y.wires().iter())
                    .map(|(x, y)| {
                        let xp = self.and(x, &neg, channel)?;
                        let yp = self.and(y, &pos, channel)?;
                        Ok(self.xor(&xp, &yp))
                    })
                    .collect::<swanky_error::Result<Vec<Self::Item>>>()?,
            ))
        })
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
    /// Compute `x == y` for binary bundles.
    fn bin_eq_bundles(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // compute (x^y == 0) for each residue
        let zs = x
            .wires()
            .iter()
            .zip_eq(y.wires().iter())
            .map(|(x, y)| {
                let xy = self.xor(x, y);
                self.negate(&xy)
            })
            .collect::<Vec<_>>();
        // and_many will return 1 only if all outputs of xnor are 1
        // indicating equality
        self.and_many(&zs, channel)
    }
}

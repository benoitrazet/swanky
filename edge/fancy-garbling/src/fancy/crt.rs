//! Module containing `CrtGadgets`, which are the CRT-based gadgets for `Fancy`.

use super::{HasModulus, bundle::ArithmeticBundleGadgets};
use crate::{
    FancyArithmetic, FancyBinary,
    fancy::bundle::{ArithmeticProjBundleGadgets, Bundle, BundleGadgets},
    util::{self},
};
use itertools::Itertools;
use std::ops::Deref;
use swanky_channel::Channel;

/// Bundle which is explicitly CRT-representation.
#[derive(Clone)]
pub struct CrtBundle<W>(Bundle<W>);

impl<W: Clone + HasModulus> CrtBundle<W> {
    /// Create a new CRT bundle from a vector of wires.
    pub fn new(ws: Vec<W>) -> CrtBundle<W> {
        CrtBundle(Bundle::new(ws))
    }

    /// Extract the underlying bundle from this CRT bundle.
    pub fn extract(self) -> Bundle<W> {
        self.0
    }

    /// Return the product of all the wires' moduli.
    pub fn composite_modulus(&self) -> u128 {
        util::product(&self.iter().map(HasModulus::modulus).collect_vec())
    }
}

impl<W: Clone + HasModulus> Deref for CrtBundle<W> {
    type Target = Bundle<W>;

    fn deref(&self) -> &Bundle<W> {
        &self.0
    }
}

impl<W: Clone + HasModulus> From<Bundle<W>> for CrtBundle<W> {
    fn from(b: Bundle<W>) -> CrtBundle<W> {
        CrtBundle(b)
    }
}

impl<F: FancyArithmetic + FancyBinary> CrtGadgets for F {}

/// Extension trait for `Fancy` providing advanced CRT gadgets based on bundles of wires.
pub trait CrtGadgets:
    FancyArithmetic + FancyBinary + ArithmeticBundleGadgets + BundleGadgets
{
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

    /// Creates a bundle of constant wires for the CRT representation of `x` under
    /// composite modulus `q`.
    fn crt_constant_bundle(
        &mut self,
        x: u128,
        q: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<CrtBundle<Self::Item>> {
        let ps = util::factor(q);
        let xs = ps.iter().map(|&p| (x % p as u128) as u16).collect_vec();
        self.constant_bundle(&xs, &ps, channel).map(CrtBundle)
    }

    /// Output a CRT bundle and interpret it mod Q.
    fn crt_output(
        &mut self,
        x: &CrtBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u128>> {
        let q = x.composite_modulus();
        Ok(self
            .output_bundle(x, channel)?
            .map(|xs| util::crt_inv_factor(&xs, q)))
    }

    /// Output a slice of CRT bundles and interpret the outputs mod Q.
    fn crt_outputs(
        &mut self,
        xs: &[CrtBundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u128>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.crt_output(x, channel)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }

    /// Subtract two CRT bundles.
    fn crt_sub(
        &mut self,
        x: &CrtBundle<Self::Item>,
        y: &CrtBundle<Self::Item>,
    ) -> CrtBundle<Self::Item> {
        CrtBundle(self.sub_bundles(x, y))
    }
}

impl<F: ArithmeticProjBundleGadgets + CrtGadgets> CrtProjGadgets for F {}

/// CRT gadgets that use projection gates.
pub trait CrtProjGadgets: ArithmeticProjBundleGadgets + CrtGadgets {
    /// Exponentiate `x` by the constant `c`.
    fn crt_cexp(
        &mut self,
        x: &CrtBundle<Self::Item>,
        c: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<CrtBundle<Self::Item>> {
        x.wires()
            .iter()
            .map(|x| {
                let p = x.modulus();
                let tab = (0..p)
                    .map(|x| ((x as u64).pow(c as u32) % p as u64) as u16)
                    .collect_vec();
                self.proj(x, p, Some(tab), channel)
            })
            .collect::<swanky_error::Result<_>>()
            .map(CrtBundle::new)
    }

    /// Compute the remainder with respect to modulus `p`.
    ///
    /// # Panics
    /// Panics if `p` is not a modulus contained in `x`.
    fn crt_rem(
        &mut self,
        x: &CrtBundle<Self::Item>,
        p: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<CrtBundle<Self::Item>> {
        let i = x.moduli().iter().position(|&q| p == q);
        assert!(i.is_some(), "`p` is not a modulus in the `x` bundle");
        let i = i.unwrap();
        let w = &x.wires()[i];
        x.moduli()
            .iter()
            .map(|&q| self.mod_change(w, q, channel))
            .collect::<swanky_error::Result<_>>()
            .map(CrtBundle::new)
    }
    /// Convert the xs bundle to PMR representation. Useful for extracting out of CRT.
    fn crt_to_pmr(
        &mut self,
        xs: &CrtBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Bundle<Self::Item>> {
        let gadget_projection_tt = |p: u16, q: u16| -> Vec<u16> {
            let pq = p as u32 + q as u32 - 1;
            let mut tab = Vec::with_capacity(pq as usize);
            for z in 0..pq {
                let mut x = 0;
                let mut y = 0;
                'outer: for i in 0..p as u32 {
                    for j in 0..q as u32 {
                        if (i + pq - j) % pq == z {
                            x = i;
                            y = j;
                            break 'outer;
                        }
                    }
                }
                debug_assert_eq!((x + pq - y) % pq, z);
                tab.push(
                    (((x * q as u32 * util::inv(q as i128, p as i128) as u32
                        + y * p as u32 * util::inv(p as i128, q as i128) as u32)
                        / p as u32)
                        % q as u32) as u16,
                );
            }
            tab
        };

        let mut gadget = |x: &Self::Item, y: &Self::Item| -> swanky_error::Result<Self::Item> {
            let p = x.modulus();
            let q = y.modulus();
            let x_ = self.mod_change(x, p + q - 1, channel)?;
            let y_ = self.mod_change(y, p + q - 1, channel)?;
            let z = self.sub(&x_, &y_);
            self.proj(&z, q, Some(gadget_projection_tt(p, q)), channel)
        };

        let n = xs.size();
        let mut x = vec![vec![None; n + 1]; n + 1];

        for j in 0..n {
            x[0][j + 1] = Some(xs.wires()[j].clone());
        }

        for i in 1..=n {
            for j in i + 1..=n {
                let z = gadget(x[i - 1][i].as_ref().unwrap(), x[i - 1][j].as_ref().unwrap())?;
                x[i][j] = Some(z);
            }
        }

        let mut zwires = Vec::with_capacity(n);
        for i in 0..n {
            zwires.push(x[i][i + 1].take().unwrap());
        }
        Ok(Bundle::new(zwires))
    }

    /// Comparison based on PMR, more expensive than crt_lt but works on more things. For
    /// it to work, there must be an extra modulus in the CRT that is not necessary to
    /// represent the values. This ensures that if x < y, the most significant PMR digit
    /// is nonzero after subtracting them. You could add a prime to your CrtBundles right
    /// before using this gadget.
    fn pmr_lt(
        &mut self,
        x: &CrtBundle<Self::Item>,
        y: &CrtBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let z = self.crt_sub(x, y);
        let mut pmr = self.crt_to_pmr(&z, channel)?;
        let w = pmr.pop().unwrap();
        let mut tab = vec![1; w.modulus() as usize];
        tab[0] = 0;
        self.proj(&w, 2, Some(tab), channel)
    }

    /// Comparison based on PMR, more expensive than crt_lt but works on more things. For
    /// it to work, there must be an extra modulus in the CRT that is not necessary to
    /// represent the values. This ensures that if x < y, the most significant PMR digit
    /// is nonzero after subtracting them. You could add a prime to your CrtBundles right
    /// before using this gadget.
    fn pmr_geq(
        &mut self,
        x: &CrtBundle<Self::Item>,
        y: &CrtBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let z = self.pmr_lt(x, y, channel)?;
        Ok(self.negate(&z))
    }
}

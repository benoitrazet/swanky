use crate::{
    CrtBundle, FancyArithmetic, FancyProj, HasModulus,
    circuit::Circuit,
    circuits::arithmetic::addition::AddMany,
    util::{as_mixed_radix, inv, product},
};
use swanky_channel::Channel;
use swanky_error::Result;

struct MixedRadixAdditionMSBOnly;

impl<F: FancyArithmetic + FancyProj> Circuit<F> for MixedRadixAdditionMSBOnly {
    type Input = Vec<CrtBundle<F::Item>>;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let xs = inputs;
        assert!(!xs.is_empty(), "`inputs` cannot be empty");
        assert!(xs.iter().all(|x| x.moduli() == xs[0].moduli()));

        let nargs = xs.len();
        let n = xs[0].wires().len();

        let mut opt_carry = None;
        let mut max_carry = 0;

        for i in 0..n - 1 {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x.wires()[i].clone()).collect::<Vec<_>>();
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
                .map(|d| backend.mod_change(d, max_val + 1, channel))
                .collect::<swanky_error::Result<Vec<_>>>()?;
            // add them up
            let sum = AddMany.execute(backend, &modded_ds, channel)?;
            // add in the carry
            let sum_with_carry = opt_carry
                .as_ref()
                .map_or(sum.clone(), |c| backend.add(&sum, c));

            // carry now contains the carry information, we just have to project it to
            // the correct moduli for the next iteration. It will either be used to
            // compute the next carry, if i < n-2, or it will be used to compute the
            // output MSB, in which case it should be the modulus of the SB
            let next_mod = if i < n - 2 {
                nargs as u16 * (xs[0].moduli()[i + 1] - 1) + max_carry + 1
            } else {
                inputs[0].moduli()[i + 1] // we will be adding the carry to the MSB
            };

            let tt = (0..=max_val)
                .map(|i| (i / q) % next_mod)
                .collect::<Vec<_>>();
            opt_carry = Some(backend.proj(&sum_with_carry, next_mod, Some(tt), channel)?);
        }

        // compute the msb
        let ds = xs
            .iter()
            .map(|x| x.wires()[n - 1].clone())
            .collect::<Vec<_>>();
        let digit_sum = AddMany.execute(backend, &ds, channel)?;
        Ok(opt_carry
            .as_ref()
            .map_or(digit_sum.clone(), |d| backend.add(&digit_sum, d)))
    }
}

/// For input [`CrtBundle`] `x` and vector of moduli `ms`, output the MSB of the
/// fractional part of `x / M`, where `M = product(ms)`.
pub struct FractionalMixedRadix;

impl<F: FancyArithmetic + FancyProj> Circuit<F> for FractionalMixedRadix {
    type Input = (CrtBundle<F::Item>, Vec<u16>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (bun, ms) = inputs;

        let ndigits = ms.len();

        let q = product(&bun.moduli());
        let M = product(ms);

        let mut ds = Vec::new();

        for wire in bun.wires().iter() {
            let p = wire.modulus();

            let mut tabs = vec![Vec::with_capacity(p as usize); ndigits];

            for x in 0..p {
                let crt_coef = inv(((q / p as u128) % p as u128) as i128, p as i128);
                let y = (M as f64 * x as f64 * crt_coef as f64 / p as f64).round() as u128 % M;
                let digits = as_mixed_radix(y, ms);
                for i in 0..ndigits {
                    tabs[i].push(digits[i]);
                }
            }

            let new_ds = tabs
                .into_iter()
                .enumerate()
                .map(|(i, tt)| backend.proj(wire, ms[i], Some(tt), channel))
                .collect::<Result<Vec<_>>>()?;

            ds.push(CrtBundle::new(new_ds));
        }

        MixedRadixAdditionMSBOnly.execute(backend, &ds, channel)
    }
}

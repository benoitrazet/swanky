use crate::{CrtBundle, FancyProj, HasModulus, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given a [`CrtBundle`] `x` and constant exponent `c`, output `x^c`.
///
/// This uses projection gates to compute the exponentiation for each modulus in
/// the CRT bundle.
pub struct ConstantExponentiation;

impl<F: FancyProj> Circuit<F> for ConstantExponentiation {
    type Input = (CrtBundle<F::Item>, u32);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, c) = inputs;
        x.wires()
            .iter()
            .map(|x| {
                let p = x.modulus();
                let tab = (0..p)
                    .map(|x| ((x as u64).pow(*c) % p as u64) as u16)
                    .collect::<Vec<_>>();
                backend.proj(x, p, Some(tab), channel)
            })
            .collect::<Result<_>>()
            .map(CrtBundle::new)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::arithmetic::ConstantExponentiation,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn constant_exponentiation() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.r#gen::<u16>() as u128 % q;
            let c = rng.gen_range(2..10);
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&ConstantExponentiation, &(x_input, c)).unwrap();
            let output = DummyVal::from_crt(&z, q);

            // Compute x^c mod q using modular arithmetic to avoid overflow
            let mut expected = 1u128;
            for _ in 0..c {
                expected = (expected * x) % q;
            }
            assert_eq!(output, expected);
        }
    }
}

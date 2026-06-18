use crate::{CrtBundle, FancyProj, circuit::Circuit, circuits::arithmetic::ModChange};
use core::marker::PhantomData;
use swanky_channel::Channel;
use swanky_error::Result;

/// Given a [`CrtBundle`] `x` and modulus `p`, compute the remainder with respect to `p`.
///
/// # Panics
/// Panics if `p` is not a modulus contained in `x`.
#[derive(Default)]
pub struct Remainder<'a>(PhantomData<&'a ()>);

impl<'a> Remainder<'a> {
    /// Create a new [`Remainder`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyProj> Circuit<F> for Remainder<'a>
where
    F::Item: 'a,
{
    type Input = (&'a CrtBundle<F::Item>, u16);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, modulus) = inputs;
        let i = x.moduli().iter().position(|&q| modulus == q);
        assert!(
            i.is_some(),
            "`modulus` {modulus} is not in the input bundle",
        );
        let i = i.unwrap();
        let w = &x.wires()[i];

        // Convert the wire modulo `modulus` to all the other moduli in the bundle.
        x.moduli()
            .iter()
            .map(|&q| ModChange.execute(backend, (w.clone(), q), channel))
            .collect::<Result<_>>()
            .map(CrtBundle::new)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::arithmetic::Remainder,
        dummy::{Dummy, DummyVal},
        util::{RngExt, factor},
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn remainder() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let factors = factor(q);

        for _ in 0..16 {
            let x = rng.r#gen::<u64>() as u128 % q;
            let p = factors[rng.gen_range(0..factors.len())];

            let x_input = DummyVal::to_crt(x, q);
            let circuit = Remainder::new();
            let z = Dummy::eval(&circuit, (&x_input, p)).unwrap();
            let output = DummyVal::from_crt(&z, q);

            assert_eq!(output, x % (p as u128));
        }
    }
}

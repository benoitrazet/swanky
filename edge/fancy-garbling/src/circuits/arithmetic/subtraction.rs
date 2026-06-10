use crate::{CrtBundle, FancyArithmetic, circuit::Circuit};
use core::marker::PhantomData;
use swanky_channel::Channel;
use swanky_error::Result;

/// Given [`CrtBundle`]s `x` and `y`, output `x - y`.
#[derive(Default)]
pub struct Subtraction<'a>(PhantomData<&'a ()>);

impl<'a> Subtraction<'a> {
    /// Create a new [`Subtraction`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic> Circuit<F> for Subtraction<'a>
where
    F::Item: 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a CrtBundle<F::Item>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.size(), y.size(), "`x` and `y` must be the same length");
        Ok(CrtBundle::new(
            x.wires()
                .iter()
                .zip(y.wires().iter())
                .map(|(x, y)| backend.sub(x, y))
                .collect(),
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::arithmetic::Subtraction,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn subtraction() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let circuit = Subtraction::new();
            let z = Dummy::eval(&circuit, &(&x_input, &y_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, (x + q - y) % q);
        }
    }
}

use crate::CrtBundle;
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyArithmetic};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given a wire `b` and a [`CrtBundle`] `x`, output `0` if `b == 0`, otherwise
/// output `x`.
///
/// This is equivalent to computing `b * x` for each wire in the bundle.
#[derive(Default)]
pub struct Mask<'a>(PhantomData<&'a ()>);

impl<'a> Mask<'a> {
    /// Create a new [`Mask`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic> Circuit<F> for Mask<'a>
where
    F::Item: 'a,
{
    type Input = (&'a F::Item, &'a CrtBundle<F::Item>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, x) = inputs;
        Ok(CrtBundle::new(
            x.wires()
                .iter()
                .map(|xwire| backend.mul(xwire, b, channel))
                .collect::<Result<_>>()?,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::arithmetic::Mask,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn mask() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let b = rng.r#gen::<bool>();
            let x = rng.r#gen::<u128>() % q;

            let b_input = DummyVal::new(b as u16, 2);
            let x_input = DummyVal::to_crt(x, q);

            let circuit = Mask::new();
            let z = Dummy::eval(&circuit, (&b_input, &x_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);

            assert_eq!(output, (b as u128) * x);
        }
    }
}

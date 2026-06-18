use crate::{
    BinaryBundle, FancyBinary,
    circuit::Circuit,
    circuits::binary::{BinaryAddition, BinaryConstant, BinaryMultiplex, BinaryTwosComplement},
};
use core::marker::PhantomData;
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`BinaryBundle`]s `x` and `y`, output `x / y`.
#[derive(Default)]
pub struct BinaryDivision<'a>(PhantomData<&'a ()>);

impl<'a> BinaryDivision<'a> {
    /// Create a new [`BinaryDivision`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryDivision<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, ys) = inputs;
        assert_eq!(xs.moduli(), ys.moduli());

        let ys_neg = BinaryTwosComplement::new().execute(backend, ys, channel)?;
        let mut acc = BinaryConstant::new(0, xs.size()).execute(backend, (), channel)?;
        let mut qs = BinaryBundle::new(Vec::new());
        for x in xs.iter().rev() {
            acc.pop();
            acc.insert(0, x.clone());
            let (res, cout) =
                BinaryAddition::default().execute(backend, (&acc, &ys_neg), channel)?;
            acc = BinaryMultiplex::new().execute(backend, (cout.clone(), &acc, &res), channel)?;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }
}

#[cfg(test)]
mod test {
    use rand::{Rng, thread_rng};

    use crate::{
        circuits::binary::BinaryDivision,
        dummy::{Dummy, DummyVal},
    };

    #[test]
    fn test_binary_division() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let mut y = rng.r#gen::<u128>() % q;
            while y == 0 {
                y = rng.r#gen::<u128>() % q;
            }
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&BinaryDivision::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x / y);
        }
    }
}

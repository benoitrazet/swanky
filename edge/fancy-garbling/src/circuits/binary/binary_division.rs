use crate::{
    BinaryBundle, FancyBinary,
    circuit::Circuit,
    circuits::binary::{BinaryAddition, BinaryConstant, BinaryMultiplex, BinaryTwosComplement},
};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`BinaryBundle`]s `x` and `y`, output `x / y`.
pub struct BinaryDivision;

impl<F: FancyBinary> Circuit<F> for BinaryDivision {
    type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, ys) = inputs;
        assert_eq!(xs.moduli(), ys.moduli());

        let ys_neg = BinaryTwosComplement.execute(backend, ys, channel)?;
        let mut acc = BinaryConstant::new(0, xs.size()).execute(backend, &(), channel)?;
        let mut qs = BinaryBundle::new(Vec::new());
        for x in xs.iter().rev() {
            acc.pop();
            acc.insert(0, x.clone());
            let (res, cout) =
                BinaryAddition.execute(backend, &(acc.clone(), ys_neg.clone()), channel)?;
            acc = BinaryMultiplex.execute(backend, &(cout.clone(), acc.clone(), res), channel)?;
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
            let output = Dummy::eval(&BinaryDivision, &(x_input, y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x / y);
        }
    }
}

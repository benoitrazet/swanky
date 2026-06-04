use crate::{
    BinaryBundle, FancyBinary,
    circuit::Circuit,
    circuits::binary::{BinaryMultiplex, BinaryTwosComplement},
};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`BinaryBundle`] `x`, output the absolute value of `x`.
pub struct BinaryAbs;

impl<F: FancyBinary> Circuit<F> for BinaryAbs {
    type Input = BinaryBundle<F::Item>;
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let x = inputs;

        let sign = x.wires().last().unwrap();
        let negated = BinaryTwosComplement.execute(backend, x, channel)?;
        BinaryMultiplex.execute(backend, &(sign.clone(), x.clone(), negated), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::binary::BinaryAbs,
        dummy::{Dummy, DummyVal},
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn binary_abs() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let output = Dummy::eval(&BinaryAbs, &x_input).unwrap();
            assert_eq!(
                DummyVal::from_binary(&output),
                if x >> (nbits - 1) > 0 {
                    ((!x) + 1) & ((1 << nbits) - 1)
                } else {
                    x
                }
            );
        }
    }
}

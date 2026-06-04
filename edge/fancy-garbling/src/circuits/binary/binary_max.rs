use crate::{BinaryBundle, FancyBinary, circuit::Circuit, circuits::binary::BinaryLessThan};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary max.
///
/// For a vector of [`BinaryBundle`]s, return the max value.
///
/// # Panics
/// This panics if the input vector is empty.
pub struct BinaryMax;

impl<F: FancyBinary> Circuit<F> for BinaryMax {
    type Input = Vec<BinaryBundle<F::Item>>;
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`xs` cannot be empty");
        inputs.iter().skip(1).try_fold(inputs[0].clone(), |x, y| {
            // Compute `x < y`.
            let pos = BinaryLessThan.execute(backend, &(x.clone(), y.clone()), channel)?;
            // Compute `!(x < y)`.
            let neg = backend.negate(&pos);
            // Compute `x * (x >= y) ^ y * (x < y)`.
            Ok(BinaryBundle::new(
                x.wires()
                    .iter()
                    .zip(y.wires().iter())
                    .map(|(x, y)| {
                        let xp = backend.and(x, &neg, channel)?;
                        let yp = backend.and(y, &pos, channel)?;
                        Ok(backend.xor(&xp, &yp))
                    })
                    .collect::<Result<Vec<F::Item>>>()?,
            ))
        })
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use super::BinaryMax;
    use crate::{
        BinaryBundle,
        dummy::{Dummy, DummyVal},
    };

    #[test]
    fn binary_max() {
        let mut rng = rand::thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let nitems = 10;

        for _ in 0..16 {
            let xs: Vec<u128> = (0..nitems).map(|_| rng.r#gen::<u128>() % q).collect();
            let max = *xs.iter().max().unwrap();
            let xs_input: Vec<BinaryBundle<DummyVal>> =
                xs.iter().map(|x| DummyVal::to_binary(*x, nbits)).collect();
            let output = Dummy::eval(&BinaryMax, &xs_input).unwrap();
            let output_val = DummyVal::from_binary(&output);
            assert_eq!(output_val, max);
        }
    }
}

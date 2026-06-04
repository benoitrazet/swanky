use crate::{BinaryBundle, FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// For a [`BinaryBundle`] `x` and an integer `n`, shift `x` by `n`, retaining
/// the size of `x`.
pub struct BinaryShift;

impl<F: FancyBinary> Circuit<F> for BinaryShift {
    type Input = (BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;

        let mut wires = bundle.wires().to_vec();
        let zero = backend.constant(0, 2, channel)?;
        for _ in 0..*n {
            wires.pop();
            wires.insert(0, zero.clone());
        }
        Ok(BinaryBundle::new(wires))
    }
}

/// For a [`BinaryBundle`] `x` and an integer `n`, shift `x` by `n` 0s, extending
/// the [`BinaryBundle`].
///
/// That is, $`x = x_1,...,x_m`$ becomes $`x_1,...,x_m,0_1,...,0_n`$.
pub struct BinaryShiftExtend;

impl<F: FancyBinary> Circuit<F> for BinaryShiftExtend {
    type Input = (BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;
        let mut wires = bundle.wires().to_vec();
        let zero = backend.constant(0, 2, channel)?;
        for _ in 0..*n {
            wires.insert(0, zero.clone());
        }
        Ok(BinaryBundle::new(wires))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::binary::{BinaryShift, BinaryShiftExtend},
        dummy::{Dummy, DummyVal},
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn shift() {
        const N: usize = 64;
        let mut rng = thread_rng();

        for _ in 0..16 {
            let shift_size = rng.r#gen::<usize>() % N;
            let x = rng.r#gen::<u64>();
            let input = DummyVal::to_binary(x as u128, N);
            let output = Dummy::eval(&BinaryShift, &(input, shift_size as usize)).unwrap();
            assert_eq!(
                DummyVal::from_binary(&output) as u64,
                x.wrapping_shl(shift_size as u32)
            );
        }
    }

    #[test]
    fn shift_extend() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let shift_size = rng.r#gen::<usize>() % nbits;
            let x = rng.r#gen::<u128>() % q;
            let input = DummyVal::to_binary(x, nbits);
            let output = Dummy::eval(&BinaryShiftExtend, &(input, shift_size)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x << shift_size);
        }
    }
}

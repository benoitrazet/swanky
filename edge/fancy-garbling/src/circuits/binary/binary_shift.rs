use crate::{BinaryBundle, FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// For a [`BinaryBundle`] `x` and an integer `n`, shift `x` left by `n`,
/// retaining the size of `x`.
pub struct BinaryLeftShift;

impl<F: FancyBinary> Circuit<F> for BinaryLeftShift {
    type Input = (BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;
        let zero = backend.constant(0, 2, channel)?;

        let mut wires = bundle.wires().to_vec();
        for _ in 0..n {
            wires.pop();
            wires.insert(0, zero.clone());
        }
        Ok(BinaryBundle::new(wires))
    }
}

/// For a [`BinaryBundle`] `x` and an integer `n`, shift `x` left by `n` 0s,
/// extending the [`BinaryBundle`].
///
/// That is, $`x = x_1,...,x_m`$ becomes $`x_1,...,x_m,0_1,...,0_n`$.
pub struct BinaryLeftShiftExtend;

impl<F: FancyBinary> Circuit<F> for BinaryLeftShiftExtend {
    type Input = (BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;
        let mut wires = bundle.wires().to_vec();
        let zero = backend.constant(0, 2, channel)?;
        for _ in 0..n {
            wires.insert(0, zero.clone());
        }
        Ok(BinaryBundle::new(wires))
    }
}

/// For a [`BinaryBundle`] `x`, integer `n`, and pad `c`, shift `x` right by
/// `n`, retaining the size of `x` and filling space on the left by `c`.
pub struct BinaryRightShift;

impl<F: FancyBinary> Circuit<F> for BinaryRightShift {
    type Input = (BinaryBundle<F::Item>, usize, F::Item);
    type Output = BinaryBundle<F::Item>;

    fn execute(&self, _: &mut F, inputs: Self::Input, _: &mut Channel) -> Result<Self::Output> {
        let (x, n, pad) = inputs;
        let mut wires: Vec<_> = Vec::with_capacity(x.wires().len());

        for i in 0..x.wires().len() {
            let src_idx = i + n;
            if src_idx >= x.wires().len() {
                wires.push(pad.clone())
            } else {
                wires.push(x.wires()[src_idx].clone())
            }
        }
        Ok(BinaryBundle::new(wires))
    }
}

/// Logical right shift.
pub struct BinaryLogicalRightShift;

impl<F: FancyBinary> Circuit<F> for BinaryLogicalRightShift {
    type Input = (BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, n) = inputs;
        let zero = backend.constant(0, 2, channel)?;
        BinaryRightShift.execute(backend, (x.clone(), n, zero), channel)
    }
}

/// Arithmetic right shift.
pub struct BinaryArithmeticRightShift;

impl<F: FancyBinary> Circuit<F> for BinaryArithmeticRightShift {
    type Input = (BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, n) = inputs;
        let pad = x.wires().last().unwrap();
        BinaryRightShift.execute(backend, (x.clone(), n, pad.clone()), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::binary::{
            BinaryArithmeticRightShift, BinaryLeftShift, BinaryLeftShiftExtend,
            binary_shift::BinaryLogicalRightShift,
        },
        dummy::{Dummy, DummyVal},
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn left_shift() {
        const N: usize = 64;
        let mut rng = thread_rng();

        for _ in 0..16 {
            let shift_size = rng.r#gen::<usize>() % N;
            let x = rng.r#gen::<u64>();
            let input = DummyVal::to_binary(x as u128, N);
            let output = Dummy::eval(&BinaryLeftShift, (input, shift_size as usize)).unwrap();
            assert_eq!(
                DummyVal::from_binary(&output) as u64,
                x.wrapping_shl(shift_size as u32)
            );
        }
    }

    #[test]
    fn left_shift_extend() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let shift_size = rng.r#gen::<usize>() % nbits;
            let x = rng.r#gen::<u128>() % q;
            let input = DummyVal::to_binary(x, nbits);
            let output = Dummy::eval(&BinaryLeftShiftExtend, (input, shift_size)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x << shift_size);
        }
    }

    #[test]
    fn logical_right_shift() {
        const N: usize = 64;
        let mut rng = thread_rng();

        for _ in 0..16 {
            let shift_size = rng.r#gen::<usize>() % N;
            let x = rng.r#gen::<u64>();
            let input = DummyVal::to_binary(x as u128, N);
            let output =
                Dummy::eval(&BinaryLogicalRightShift, (input, shift_size as usize)).unwrap();
            assert_eq!(DummyVal::from_binary(&output) as u64, x >> shift_size);
        }
    }

    #[test]
    fn arithmetic_right_shift() {
        const N: usize = 64;
        const Q: u128 = 1 << N;
        let mut rng = thread_rng();

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % Q;
            let shift_size = rng.r#gen::<usize>() % N;
            let x_input = DummyVal::to_binary(x, N);
            let output = Dummy::eval(&BinaryArithmeticRightShift, (x_input, shift_size)).unwrap();
            assert_eq!(
                DummyVal::from_binary(&output) as i64,
                (x as i64) >> shift_size
            );
        }
    }
}

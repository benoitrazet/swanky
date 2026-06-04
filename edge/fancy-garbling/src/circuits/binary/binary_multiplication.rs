use crate::{
    BinaryBundle, FancyBinary,
    circuit::{Circuit, CircuitInputMapper},
    circuits::binary::{
        BinaryAddition, BinaryAdditionNoCarry, BinaryConstant, BinaryShift, BinaryShiftExtend,
    },
    util::u128_to_bits,
};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`BinaryBundle`] inputs `x` and `y`, output `x * y`.
pub struct BinaryMultiplication;

impl<F: FancyBinary> Circuit<F> for BinaryMultiplication {
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

        let xwires = xs.wires();
        let ywires = ys.wires();

        let zero = backend.constant(0, 2, channel)?;

        let mut sum = xwires
            .iter()
            .map(|x| backend.and(x, &ywires[0], channel))
            .collect::<Result<_>>()
            .map(BinaryBundle::new)?;

        sum.pad(&zero, 1);

        for (i, ywire) in ywires.iter().enumerate().take(xwires.len()).skip(1) {
            let mul = xwires
                .iter()
                .map(|x| backend.and(x, ywire, channel))
                .collect::<Result<_>>()
                .map(BinaryBundle::new)?;
            let shifted = BinaryShiftExtend.execute(backend, &(mul, i), channel)?;
            let res = BinaryAddition.execute(backend, &(sum, shifted), channel)?;
            sum = res.0;
            sum.push(res.1);
        }

        Ok(sum)
    }
}

/// For [`BinaryBundle`]s `x` and `y`, return the the lower-order half of `x *
/// y`.
pub struct BinaryMultiplicationLowerHalf;

impl<F: FancyBinary> Circuit<F> for BinaryMultiplicationLowerHalf {
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

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| backend.and(x, &ywires[0], channel))
            .collect::<Result<_>>()
            .map(BinaryBundle::new)?;

        for (i, ywire) in ywires.iter().enumerate().take(xwires.len()).skip(1) {
            let mul = xwires
                .iter()
                .map(|x| backend.and(x, ywire, channel))
                .collect::<Result<_>>()
                .map(BinaryBundle::new)?;
            let shifted = BinaryShift.execute(backend, &(mul, i), channel)?;
            sum = BinaryAdditionNoCarry.execute(backend, &(sum, shifted), channel)?;
        }
        Ok(sum)
    }
}

/// For [`BinaryBundle`] `x`, constant `c`, and bitlength `n`, output `x * c`,
/// where the output is of bitlength `n`.
pub struct BinaryConstantMultiplication;

impl<F: FancyBinary> Circuit<F> for BinaryConstantMultiplication {
    type Input = (BinaryBundle<F::Item>, u128, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, c, nbits) = inputs;
        let zero = BinaryConstant::new(0, *nbits).execute(backend, &(), channel)?;
        u128_to_bits(*c, *nbits)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b > 0 { Some(i) } else { None })
            .try_fold(zero, |z, shift_amt| {
                let s = BinaryShift.execute(backend, &(x.clone(), shift_amt), channel)?;
                BinaryAdditionNoCarry.execute(backend, &(z, s), channel)
            })
    }
}

/// Circuit for testing [`BinaryMultiplication`].
pub struct TestBinaryMultiplication(pub usize);

impl<F: FancyBinary> Circuit<F> for TestBinaryMultiplication {
    type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        BinaryMultiplication.execute(backend, inputs, channel)
    }
}

impl<F: FancyBinary> CircuitInputMapper<F> for TestBinaryMultiplication {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), self.0 * 2);
        let (x, y) = inputs.split_at(self.0);
        let x = BinaryBundle::new(x.to_vec());
        let y = BinaryBundle::new(y.to_vec());
        (x, y)
    }

    fn ninputs(&self) -> usize {
        self.0 * 2
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::binary::{
            BinaryConstantMultiplication, BinaryMultiplication, BinaryMultiplicationLowerHalf,
        },
        dummy::{Dummy, DummyVal},
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn binary_multiplication() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&BinaryMultiplication, &(x_input, y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x * y);
        }
    }

    #[test]
    fn binary_multiplication_lower_half() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&BinaryMultiplicationLowerHalf, &(x_input, y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), (x * y) % q);
        }
    }

    #[test]
    fn binary_constant_multiplication() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let c = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let output = Dummy::eval(&BinaryConstantMultiplication, &(x_input, c, nbits)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), (x * c) % q);
        }
    }
}

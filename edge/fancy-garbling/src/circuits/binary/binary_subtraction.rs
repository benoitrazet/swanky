use crate::{BinaryBundle, BinaryGadgets, FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary subtract.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x - y, underflow)`, where
/// `underflow` indicates `y != 0 && x >= y`.
pub struct BinarySubtraction;

impl<F: FancyBinary> Circuit<F> for BinarySubtraction {
    type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
    type Output = (BinaryBundle<F::Item>, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert_eq!(inputs.0.moduli(), inputs.1.moduli());
        let (x, y) = inputs;
        let neg_y = backend.bin_twos_complement(y, channel)?;
        backend.bin_addition(x, &neg_y, channel)
    }
}

pub mod test {
    use super::*;
    use crate::circuit::CircuitExecutor;

    /// Circuit for testing [`BinarySubtraction`].
    pub struct TestBinarySubtraction(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestBinarySubtraction {
        type Input = <BinarySubtraction as Circuit<F>>::Input;
        type Output = <BinarySubtraction as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: &Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinarySubtraction.execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinary> CircuitExecutor<F> for TestBinarySubtraction {
        fn map(&self, inputs: Vec<<F as crate::Fancy>::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0 * 2);
            let (x, y) = inputs.split_at(self.0);
            (BinaryBundle::new(x.to_vec()), BinaryBundle::new(y.to_vec()))
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn binary_subtraction() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = TestBinarySubtraction(nbits);

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let outputs = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(
                DummyVal::from_binary(&outputs.0),
                x.overflowing_sub(y).0 % q
            );
            assert_eq!(outputs.1.val(), (y != 0 && x >= y) as u16);
        }
    }
}

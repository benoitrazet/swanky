use crate::{
    BinaryBundle, FancyBinary,
    circuit::Circuit,
    circuits::binary::{BinarySubtraction, OrMany},
};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary less than.
///
/// For [`BinaryBundle`]s `x` and `y`, return `x < y`.
pub struct BinaryLessThan;

impl<F: FancyBinary> Circuit<F> for BinaryLessThan {
    type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert_eq!(inputs.0.moduli(), inputs.1.moduli());
        let (x, y) = inputs;

        // underflow indicates y != 0 && x >= y
        // requiring special care to remove the y != 0, which is what follows.
        let (_, lhs) =
            BinarySubtraction.execute(backend, &(x.to_owned(), y.to_owned()), channel)?;

        // Now we build a clause equal to (y == 0 || x >= y), which we can OR with
        // lhs to remove the y==0 aspect.
        // check if y==0
        let y_contains_1 = OrMany.execute(backend, y.wires(), channel)?;
        let y_eq_0 = backend.negate(&y_contains_1);

        // if x != 0, then x >= y, ... assuming x is not negative
        let x_contains_1 = OrMany.execute(backend, x.wires(), channel)?;

        // y == 0 && x >= y
        let rhs = backend.and(&y_eq_0, &x_contains_1, channel)?;

        // (y != 0 && x >= y) || (y == 0 && x >= y)
        // => x >= y && (y != 0 || y == 0)\
        // => x >= y && 1
        // => x >= y
        let geq = backend.or(&lhs, &rhs, channel)?;
        let ngeq = backend.negate(&geq);

        let xy_neq_0 = backend.or(&y_contains_1, &x_contains_1, channel)?;
        backend.and(&xy_neq_0, &ngeq, channel)
    }
}

pub mod test {
    use super::*;
    use crate::circuit::CircuitExecutor;

    /// Circuit for testing [`BinaryLessThan`].
    pub struct TestBinaryLessThan(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestBinaryLessThan {
        type Input = <BinaryLessThan as Circuit<F>>::Input;
        type Output = <BinaryLessThan as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: &Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryLessThan.execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinary> CircuitExecutor<F> for TestBinaryLessThan {
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
    fn binary_less_than() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = TestBinaryLessThan(nbits);

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(output.val() > 0, x < y);
        }
    }
}

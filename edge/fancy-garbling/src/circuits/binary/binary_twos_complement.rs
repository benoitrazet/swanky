use crate::{
    BinaryBundle, FancyBinary,
    circuit::Circuit,
    circuits::binary::{BinaryAdditionNoCarry, BinaryConstant},
};
use core::marker::PhantomData;
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary two's complement.
#[derive(Default)]
pub struct BinaryTwosComplement<'a>(PhantomData<&'a ()>);

impl<'a> BinaryTwosComplement<'a> {
    /// Create a new [`BinaryTwosComplement`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryTwosComplement<'a>
where
    F::Item: 'a,
{
    type Input = &'a BinaryBundle<F::Item>;
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        input: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let not_xs = BinaryBundle::new(
            input
                .wires()
                .iter()
                .map(|x| backend.negate(x))
                .collect::<Vec<_>>(),
        );
        let one = BinaryConstant::new(1, input.size()).execute(backend, (), channel)?;
        BinaryAdditionNoCarry::new().execute(backend, (&not_xs, &one), channel)
    }
}

pub mod test {
    use crate::circuit::CircuitInputMapper;

    use super::*;

    /// Circuit for testing [`BinaryTwosComplement`].
    pub struct TestBinaryTwosComplement(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestBinaryTwosComplement {
        type Input = BinaryBundle<F::Item>;
        type Output = BinaryBundle<F::Item>;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryTwosComplement::new().execute(backend, &inputs, channel)
        }
    }

    impl<F: FancyBinary> CircuitInputMapper<F> for TestBinaryTwosComplement {
        fn map(&self, inputs: Vec<<F as crate::Fancy>::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0);
            BinaryBundle::new(inputs)
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn binary_twos_complement() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = TestBinaryTwosComplement(nbits);

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let output = Dummy::eval(&c, x_input).unwrap();
            assert_eq!(DummyVal::from_binary(&output), (((!x) % q) + 1) % q);
        }
    }
}

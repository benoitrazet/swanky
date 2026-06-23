use crate::{
    BinaryBundle, BinaryBundleAndItem,
    circuits::binary::{BinaryAdder, XorMany},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary addition.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x + y, c)`, where `c` is the
/// carry bit.
#[derive(Default)]
pub struct BinaryAddition<'a>(PhantomData<&'a ()>);

impl<'a> BinaryAddition<'a> {
    /// Create a new [`BinaryAddition`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryAddition<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = BinaryBundleAndItem<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.moduli(), y.moduli());
        let xwires = x.wires();
        let ywires = y.wires();
        let (mut z, mut c) =
            BinaryAdder::new().execute(backend, (&xwires[0], &ywires[0], None), channel)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() {
            let res =
                BinaryAdder::new().execute(backend, (&xwires[i], &ywires[i], Some(&c)), channel)?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        Ok(BinaryBundleAndItem(BinaryBundle::new(bs), c))
    }
}

/// Binary addition without a carry.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x + y)`.
#[derive(Default)]
pub struct BinaryAdditionNoCarry<'a>(PhantomData<&'a ()>);

impl<'a> BinaryAdditionNoCarry<'a> {
    /// Create a new [`BinaryAdditionNoCarry`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryAdditionNoCarry<'a>
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
        let (x, y) = inputs;
        assert_eq!(x.moduli(), y.moduli());
        let xwires = x.wires();
        let ywires = y.wires();
        let (mut z, mut c) =
            BinaryAdder::new().execute(backend, (&xwires[0], &ywires[0], None), channel)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() - 1 {
            let res =
                BinaryAdder::new().execute(backend, (&xwires[i], &ywires[i], Some(&c)), channel)?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        // XOR instead of using `BinaryAdder`.
        let xor_inputs = [
            xwires.last().unwrap().clone(),
            ywires.last().unwrap().clone(),
            c,
        ];
        z = XorMany::new().execute(backend, &xor_inputs[..], channel)?;
        bs.push(z);
        Ok(BinaryBundle::new(bs))
    }
}

pub mod test {
    use super::*;
    use fancy_traits::CircuitInputMapper;

    /// Circuit for testing [`BinaryAddition`].
    pub struct TestBinaryAddition(pub usize);

    impl<F: FancyBinary> Circuit<F> for TestBinaryAddition {
        type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
        type Output = BinaryBundleAndItem<F::Item>;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryAddition::new().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary> CircuitInputMapper<F> for TestBinaryAddition {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
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
    fn binary_addition() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let circuit = BinaryAddition::new();

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let outputs = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&outputs.0), (x + y) % q);
            assert_eq!(outputs.1.val(), (x + y >= q) as u16);
        }
    }

    #[test]
    fn binary_addition_no_carry() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&BinaryAdditionNoCarry::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), (x + y) % q);
        }
    }
}

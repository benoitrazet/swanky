use crate::{
    BinaryBundle, FancyBinary,
    circuit::Circuit,
    circuits::binary::{BinaryAdder, XorMany},
};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary addition.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x + y, c)`, where `c` is the
/// carry bit.
pub struct BinaryAddition;

impl<F: FancyBinary> Circuit<F> for BinaryAddition {
    type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
    type Output = (BinaryBundle<F::Item>, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert_eq!(inputs.0.moduli(), inputs.1.moduli());
        let xwires = inputs.0.wires();
        let ywires = inputs.1.wires();
        let (mut z, mut c) = BinaryAdder.execute(
            backend,
            &(xwires[0].clone(), ywires[0].clone(), None),
            channel,
        )?;
        let mut bs = vec![z];
        for i in 1..xwires.len() {
            let res = BinaryAdder.execute(
                backend,
                &(xwires[i].clone(), ywires[i].clone(), Some(c)),
                channel,
            )?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        Ok((BinaryBundle::new(bs), c))
    }
}

/// Binary addition without a carry.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x + y)`.
pub struct BinaryAdditionNoCarry;

impl<F: FancyBinary> Circuit<F> for BinaryAdditionNoCarry {
    type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert_eq!(inputs.0.moduli(), inputs.1.moduli());
        let xwires = inputs.0.wires();
        let ywires = inputs.1.wires();
        let (mut z, mut c) = BinaryAdder.execute(
            backend,
            &(xwires[0].clone(), ywires[0].clone(), None),
            channel,
        )?;
        let mut bs = vec![z];
        for i in 1..xwires.len() - 1 {
            let res = BinaryAdder.execute(
                backend,
                &(xwires[i].clone(), ywires[i].clone(), Some(c)),
                channel,
            )?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        // XOR instead of using `BinaryAdder`.
        z = XorMany.execute(
            backend,
            &[
                xwires.last().unwrap().clone(),
                ywires.last().unwrap().clone(),
                c,
            ]
            .to_vec(),
            channel,
        )?;
        bs.push(z);
        Ok(BinaryBundle::new(bs))
    }
}

pub mod test {
    use super::*;
    use crate::circuit::CircuitInputMapper;

    /// Circuit for testing [`BinaryAddition`].
    pub struct TestBinaryAddition(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestBinaryAddition {
        type Input = <BinaryAddition as Circuit<F>>::Input;
        type Output = <BinaryAddition as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: &Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryAddition.execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinary> CircuitInputMapper<F> for TestBinaryAddition {
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
    fn binary_addition() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = TestBinaryAddition(nbits);

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let outputs = Dummy::eval(&c, &(x_input, y_input)).unwrap();
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
            let output = Dummy::eval(&BinaryAdditionNoCarry, &(x_input, y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), (x + y) % q);
        }
    }
}

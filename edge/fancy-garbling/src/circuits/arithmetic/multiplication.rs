use crate::{CrtBundle, FancyArithmetic, circuit::Circuit, util::crt};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given [`CrtBundle`]s `x` and `y`, output `x * y`.
pub struct Multiplication;

impl<F: FancyArithmetic> Circuit<F> for Multiplication {
    type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.size(), y.size());
        let bundle = x
            .wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| backend.mul(x, y, channel))
            .collect::<Result<Vec<_>>>()?;
        Ok(CrtBundle::new(bundle))
    }
}

/// Given [`CrtBundle`] `x` and constant `c`, output `x * c`.
pub struct ConstantMultiplication;

impl<F: FancyArithmetic> Circuit<F> for ConstantMultiplication {
    type Input = (CrtBundle<F::Item>, u128);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, c) = inputs;
        let cs = crt(*c, &x.moduli());
        Ok(CrtBundle::new(
            x.wires()
                .iter()
                .zip(cs)
                .map(|(x, c)| backend.cmul(x, c))
                .collect::<Vec<_>>(),
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::arithmetic::{ConstantMultiplication, Multiplication},
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.r#gen::<u64>() as u128 % q;
            let y = rng.r#gen::<u64>() as u128 % q;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let z = Dummy::eval(&Multiplication, &(x_input, y_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, (x * y) % q);
        }
    }

    #[test]
    fn constant_multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.r#gen::<u64>() as u128 % q;
            let c = rng.r#gen::<u64>() as u128 % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&ConstantMultiplication, &(x_input, c)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, (x * c) % q);
        }
    }
}

use crate::{CrtBundle, FancyArithmetic, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given [`CrtBundle`]s `x` and `y`, output `x + y`.
pub struct Addition;

impl<F: FancyArithmetic> Circuit<F> for Addition {
    type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.size(), y.size(), "`x` and `y` must be the same length");
        Ok(CrtBundle::new(
            x.wires()
                .iter()
                .zip(y.wires().iter())
                .map(|(x, y)| backend.add(x, y))
                .collect(),
        ))
    }
}

pub struct AddMany;

impl<F: FancyArithmetic> Circuit<F> for AddMany {
    type Input = Vec<F::Item>;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(inputs.len() >= 2, "`args.len()` must be two or more");
        let mut z = inputs[0].clone();
        for x in inputs.iter().skip(1) {
            z = backend.add(&z, x);
        }
        Ok(z)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::arithmetic::Addition,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let y = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let z = Dummy::eval(&Addition, &(x_input, y_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, (x + y) % q);
        }
    }
}

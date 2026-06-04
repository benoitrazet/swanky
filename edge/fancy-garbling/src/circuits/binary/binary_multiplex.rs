use crate::{BinaryBundle, FancyBinary, circuit::Circuit, circuits::binary::Mux};
use swanky_channel::Channel;
use swanky_error::Result;

/// For input `(b, xs, ys)`, output `xs` if `b == 0`, and `ys` otherwise.
pub struct BinaryMultiplex;

impl<F: FancyBinary> Circuit<F> for BinaryMultiplex {
    type Input = (F::Item, BinaryBundle<F::Item>, BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, xs, ys) = inputs;
        xs.wires()
            .iter()
            .zip(ys.wires().iter())
            .map(|(x, y)| Mux.execute(backend, &(b.clone(), x.clone(), y.clone()), channel))
            .collect::<Result<Vec<_>>>()
            .map(BinaryBundle::new)
    }
}

#[cfg(test)]
mod test {
    use super::BinaryMultiplex;
    use crate::dummy::{Dummy, DummyVal};
    use rand::Rng;

    #[test]
    fn binary_multiplex() {
        let mut rng = rand::thread_rng();
        let nbits = 1 + (rng.r#gen::<usize>() % 200);
        let x = rng.r#gen::<u128>() % (nbits as u128);
        let y = rng.r#gen::<u128>() % (nbits as u128);
        let x_inputs = DummyVal::to_binary(x, nbits);
        let y_inputs = DummyVal::to_binary(y, nbits);

        for b in 0..=1 {
            let output = Dummy::eval(
                &BinaryMultiplex,
                &(DummyVal::new(b, 2), x_inputs.clone(), y_inputs.clone()),
            )
            .unwrap();
            assert_eq!(DummyVal::from_binary(&output), if b == 0 { x } else { y });
        }
    }
}

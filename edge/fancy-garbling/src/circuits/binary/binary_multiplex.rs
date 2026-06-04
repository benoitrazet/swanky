use crate::{
    BinaryBundle, FancyBinary, circuit::Circuit, circuits::binary::Mux, util::u128_to_bits,
};
use swanky_channel::Channel;
use swanky_error::Result;

/// For bit `b` and [`BinaryBundle`]s `x` and `y`, output `x` if `b == 0`, and
/// `y` otherwise.
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

/// For bit `b` and constants `c1` and `c2` of bitlength `n`, output `c1` if `b
/// == 0` and `c2` otherwise.
pub struct BinaryMultiplexConstantBits;

impl<F: FancyBinary> Circuit<F> for BinaryMultiplexConstantBits {
    type Input = (F::Item, u128, u128, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, c1, c2, nbits) = inputs;

        let c1_bs = u128_to_bits(*c1, *nbits)
            .into_iter()
            .map(|x: u16| x > 0)
            .collect::<Vec<_>>();
        let c2_bs = u128_to_bits(*c2, *nbits)
            .into_iter()
            .map(|x: u16| x > 0)
            .collect::<Vec<_>>();
        c1_bs
            .into_iter()
            .zip(c2_bs)
            .map(|(b1, b2)| backend.mux_constant_bits(b, b1, b2, channel))
            .collect::<Result<_>>()
            .map(BinaryBundle::new)
    }
}

#[cfg(test)]
mod test {
    use super::BinaryMultiplex;
    use crate::{
        circuits::binary::BinaryMultiplexConstantBits,
        dummy::{Dummy, DummyVal},
    };
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

    #[test]
    fn binary_multiplex_constant_bits() {
        let mut rng = rand::thread_rng();
        let nbits = 1 + (rng.r#gen::<usize>() % 200);
        let x = rng.r#gen::<u128>() % (nbits as u128);
        let y = rng.r#gen::<u128>() % (nbits as u128);

        for b in 0..=1 {
            let output = Dummy::eval(
                &BinaryMultiplexConstantBits,
                &(DummyVal::new(b, 2), x, y, nbits),
            )
            .unwrap();
            assert_eq!(DummyVal::from_binary(&output), if b == 0 { x } else { y });
        }
    }
}

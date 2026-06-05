use crate::{FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// For input `(b, x, y)` return `x` if `b == 0`, otherwise return `y`.
pub struct Mux;

impl<F: FancyBinary> Circuit<F> for Mux {
    type Input = (F::Item, F::Item, F::Item);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        // The mux can be computed as `b (x ^ y) ^ x`.
        let (b, x, y) = inputs;
        let xor = backend.xor(x, y);
        let and = backend.and(b, &xor, channel)?;
        Ok(backend.xor(&and, x))
    }
}

/// For input `(b, c1, c2)`, return `c1` if `b == 0`, otherwise return `c2`.
pub struct MuxConstants;

impl<F: FancyBinary> Circuit<F> for MuxConstants {
    type Input = (F::Item, bool, bool);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, c1, c2) = inputs;
        match (c1, c2) {
            (false, true) => Ok(b.clone()),
            (true, false) => Ok(backend.negate(b)),
            (false, false) => backend.constant(0, 2, channel),
            (true, true) => backend.constant(1, 2, channel),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Mux;
    use crate::{
        circuits::binary::mux::MuxConstants,
        dummy::{Dummy, DummyVal},
    };

    #[test]
    fn mux() {
        for b in 0..=1 {
            for x in 0..=1 {
                for y in 0..=1 {
                    let output = Dummy::eval(
                        &Mux,
                        &(
                            DummyVal::new(b, 2),
                            DummyVal::new(x, 2),
                            DummyVal::new(y, 2),
                        ),
                    )
                    .unwrap();
                    assert_eq!(output.val(), if b == 0 { x } else { y });
                }
            }
        }
    }

    #[test]
    fn mux_constants() {
        for b in 0..=1 {
            for x in 0..=1 {
                for y in 0..=1 {
                    let output =
                        Dummy::eval(&MuxConstants, &(DummyVal::new(b, 2), x != 0, y != 0)).unwrap();
                    assert_eq!(output.val(), if b == 0 { x } else { y });
                }
            }
        }
    }
}

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

#[cfg(test)]
mod test {
    use super::Mux;
    use crate::dummy::{Dummy, DummyVal};

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
}

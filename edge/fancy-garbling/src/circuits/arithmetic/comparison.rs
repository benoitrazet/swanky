use crate::{
    CrtBundle, FancyArithmetic, FancyBinary, FancyProj,
    circuit::Circuit,
    circuits::arithmetic::{FractionalMixedRadix, Subtraction},
    util::get_ms,
};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`CrtBundle`] `x`, return 0 if `x >= 0`, 1 otherwise.
pub struct Sign;

impl<F: FancyArithmetic + FancyProj> Circuit<F> for Sign {
    type Input = (CrtBundle<F::Item>, String);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, accuracy) = inputs;
        let factors_of_m = get_ms(x, accuracy);
        let res =
            FractionalMixedRadix.execute(backend, &(x.clone(), factors_of_m.clone()), channel)?;
        let p = factors_of_m.last().unwrap();
        let tt = (0..*p).map(|x| (x >= p / 2) as u16).collect::<Vec<_>>();
        backend.proj(&res, 2, Some(tt), channel)
    }
}

/// For [`CrtBundle`]s `x` and `y`, return `x < y`.
pub struct LessThan;

impl<F: FancyArithmetic + FancyProj> Circuit<F> for LessThan {
    type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>, String);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y, accuracy) = inputs;
        let z = Subtraction.execute(backend, &(x.clone(), y.clone()), channel)?;
        Sign.execute(backend, &(z, accuracy.to_string()), channel)
    }
}

/// For [`CrtBundle`]s `x` and `y`, return `x >= y`.
pub struct GreaterThanOrEqual;

impl<F: FancyBinary + FancyArithmetic + FancyProj> Circuit<F> for GreaterThanOrEqual {
    type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>, String);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let z = LessThan.execute(backend, inputs, channel)?;
        Ok(backend.negate(&z))
    }
}

/// For a vector of [`CrtBundle`]s `xs`, return `max(xs)`.
pub struct Max;

impl<F: FancyBinary + FancyArithmetic + FancyProj> Circuit<F> for Max {
    type Input = (Vec<CrtBundle<F::Item>>, String);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, accuracy) = inputs;
        assert!(!xs.is_empty(), "`xs` cannot be empty");

        xs.iter().skip(1).try_fold(xs[0].clone(), |x, y| {
            let pos = LessThan.execute(
                backend,
                &(x.clone(), y.clone(), accuracy.to_string()),
                channel,
            )?;
            let neg = backend.negate(&pos);
            Ok(CrtBundle::new(
                x.wires()
                    .iter()
                    .zip(y.wires().iter())
                    .map(|(x, y)| {
                        let xp = backend.mul(x, &neg, channel)?;
                        let yp = backend.mul(y, &pos, channel)?;
                        Ok(backend.add(&xp, &yp))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ))
        })
    }
}

/// For [`CrtBundle`] `x`, if `x >= 0` return `1`, otherwise return `-1`, where
/// `-1` is interpreted as `Q - 1` and `Q` is the modulus of `x`.
///
/// If `output_moduli` is provided, output the result using the provided moduli.
pub struct Sgn;

impl<F: FancyArithmetic + FancyProj> Circuit<F> for Sgn {
    type Input = (CrtBundle<F::Item>, String, Option<Vec<u16>>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, accuracy, output_moduli) = inputs;
        let sign = Sign.execute(backend, &(x.clone(), accuracy.to_string()), channel)?;
        output_moduli
            .clone()
            .unwrap_or(x.moduli())
            .iter()
            .map(|&p| {
                let tt = vec![1, p - 1];
                backend.proj(&sign, p, Some(tt), channel)
            })
            .collect::<Result<_>>()
            .map(CrtBundle::new)
    }
}

/// For [`CrtBundle`] `x`, output `max(0, x)`.
pub struct ReLU;

impl<F: FancyArithmetic + FancyProj> Circuit<F> for ReLU {
    type Input = (CrtBundle<F::Item>, String, Option<Vec<u16>>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, accuracy, output_moduli) = inputs.clone();
        let factors_of_m = get_ms(&x, &accuracy);
        let res =
            FractionalMixedRadix.execute(backend, &(x.clone(), factors_of_m.clone()), channel)?;

        // project the MSB to 0/1, whether or not it is less than p/2
        let p = *factors_of_m.last().unwrap();
        let mask_tt = (0..p).map(|x| (x < p / 2) as u16).collect::<Vec<_>>();
        let mask = backend.proj(&res, 2, Some(mask_tt), channel)?;

        // use the mask to either output x or 0
        output_moduli
            .map(|ps| x.with_moduli(&ps))
            .unwrap_or(x.extract())
            .wires()
            .iter()
            .map(|x| backend.mul(x, &mask, channel))
            .collect::<Result<_>>()
            .map(CrtBundle::new)
    }
}

#[cfg(test)]
mod test {
    use rand::{Rng, thread_rng};

    use crate::{
        circuits::arithmetic::{
            ReLU, Sgn,
            comparison::{GreaterThanOrEqual, LessThan, Max, Sign},
        },
        dummy::{Dummy, DummyVal},
        util::modulus_with_width,
    };

    #[test]
    fn sign() {
        let mut rng = thread_rng();
        let accuracy = "100%".to_string();
        let q = modulus_with_width(10);

        // Check that `Sign(0) == 0`.
        let x = 0;
        let x_input = DummyVal::to_crt(x, q);
        let output = Dummy::eval(&Sign, &(x_input, accuracy.clone())).unwrap();
        assert_eq!(output.val(), if x < q / 2 { 0 } else { 1 });

        for _ in 0..64 {
            let x = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_crt(x, q);
            let output = Dummy::eval(&Sign, &(x_input, accuracy.clone())).unwrap();
            assert_eq!(output.val(), if x < q / 2 { 0 } else { 1 });
        }
    }

    #[test]
    fn less_than() {
        let mut rng = thread_rng();
        let accuracy = "100%".to_string();
        let q = modulus_with_width(10);

        // Check that `x < x` works.
        let x = rng.r#gen::<u128>() % q / 2;
        let x_input = DummyVal::to_crt(x, q);
        let output = Dummy::eval(&LessThan, &(x_input.clone(), x_input, accuracy.clone())).unwrap();
        assert_eq!(output.val(), (x < x) as u16);

        for _ in 0..64 {
            let x = rng.r#gen::<u128>() % q / 2;
            let y = rng.r#gen::<u128>() % q / 2;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let output = Dummy::eval(&LessThan, &(x_input, y_input, accuracy.clone())).unwrap();
            assert_eq!(output.val(), (x < y) as u16);
        }
    }

    #[test]
    fn greater_than_or_equal() {
        let mut rng = thread_rng();
        let accuracy = "100%".to_string();
        let q = modulus_with_width(10);

        // Check that `x >= x` works.
        let x = rng.r#gen::<u128>() % q / 2;
        let x_input = DummyVal::to_crt(x, q);
        let output = Dummy::eval(
            &GreaterThanOrEqual,
            &(x_input.clone(), x_input, accuracy.clone()),
        )
        .unwrap();
        assert_eq!(output.val(), (x >= x) as u16);

        for _ in 0..64 {
            let x = rng.r#gen::<u128>() % q / 2;
            let y = rng.r#gen::<u128>() % q / 2;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let output =
                Dummy::eval(&GreaterThanOrEqual, &(x_input, y_input, accuracy.clone())).unwrap();
            assert_eq!(output.val(), (x >= y) as u16);
        }
    }

    #[test]
    fn max() {
        let mut rng = thread_rng();
        let accuracy = "100%".to_string();
        let q = modulus_with_width(10);

        for _ in 0..16 {
            let inputs = (0..100)
                .map(|_| rng.r#gen::<u128>() % (q / 2))
                .collect::<Vec<_>>();
            let expected = *inputs.iter().max().unwrap();

            let inputs = inputs
                .into_iter()
                .map(|x| DummyVal::to_crt(x, q))
                .collect::<Vec<_>>();
            let z = Dummy::eval(&Max, &(inputs, accuracy.clone())).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn sgn() {
        let mut rng = thread_rng();
        let accuracy = "100%".to_string();
        let q = modulus_with_width(10);

        // Check that `Sign(0) == 1`.
        let x = 0;
        let x_input = DummyVal::to_crt(x, q);
        let z = Dummy::eval(&Sgn, &(x_input, accuracy.clone(), None)).unwrap();
        let output = DummyVal::from_crt(&z, q);
        assert_eq!(output, if x < q / 2 { 1 } else { q - 1 });

        for _ in 0..64 {
            let x = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&Sgn, &(x_input, accuracy.clone(), None)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, if x < q / 2 { 1 } else { q - 1 });
        }
    }

    #[test]
    fn relu() {
        let mut rng = thread_rng();
        let accuracy = "100%".to_string();
        let q = modulus_with_width(10);

        // Check that `Sign(0) == 1`.
        let x = 0;
        let x_input = DummyVal::to_crt(x, q);
        let z = Dummy::eval(&ReLU, &(x_input, accuracy.clone(), None)).unwrap();
        let output = DummyVal::from_crt(&z, q);
        assert_eq!(output, if x < q / 2 { x } else { 0 });

        for _ in 0..64 {
            let x = rng.r#gen::<u128>() % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&ReLU, &(x_input, accuracy.clone(), None)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, if x < q / 2 { x } else { 0 });
        }
    }
}

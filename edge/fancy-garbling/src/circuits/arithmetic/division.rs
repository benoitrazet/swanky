use crate::{
    CrtBundle, CrtGadgets, FancyArithmetic, FancyBinary, FancyProj,
    circuit::Circuit,
    circuits::arithmetic::{
        Addition, ConstantMultiplication, Multiplication, PmrGreaterThanOrEqual, Subtraction,
    },
    util::product,
};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`CrtBundle`]s `x` and `y`, output `x / y`.
///
/// The inputs are required to have an extra (unused) prime. That is, for
/// modulus $`Q = \prod_{i = 1,...,n} q_i`$, plaintext inputs `x` and `y` must
/// be modulo $`Q / q_n`$.
pub struct Division;

impl<F: FancyBinary + FancyArithmetic + FancyProj + CrtGadgets> Circuit<F> for Division {
    type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.moduli(), y.moduli());

        let q = x.composite_modulus();

        // Compute l based on the assumption that the last prime is unused.
        let nprimes = x.moduli().len();
        let qs_ = &x.moduli()[..nprimes - 1];
        let q_ = product(qs_);
        let l = 128 - q_.leading_zeros();

        let mut quotient = backend.crt_constant_bundle(0, q, channel)?;
        let mut a = x.clone();

        let one = backend.crt_constant_bundle(1, q, channel)?;
        for i in 0..l {
            let b = 2u128.pow(l - i - 1);
            let mut pb = q_ / b;
            if q_.is_multiple_of(b) {
                pb -= 1;
            }

            let tmp = ConstantMultiplication.execute(backend, &(y.clone(), b), channel)?;
            let c1 = PmrGreaterThanOrEqual.execute(backend, &(a.clone(), tmp.clone()), channel)?;

            let pb_crt = backend.crt_constant_bundle(pb, q, channel)?;
            let c2 = PmrGreaterThanOrEqual.execute(backend, &(pb_crt, y.clone()), channel)?;

            let c = backend.and(&c1, &c2, channel)?;

            let c_ws = one
                .iter()
                .map(|w| backend.mul(w, &c, channel))
                .collect::<Result<Vec<_>>>()?;
            let c_crt = CrtBundle::new(c_ws);

            let b_if = ConstantMultiplication.execute(backend, &(c_crt.clone(), b), channel)?;
            quotient = Addition.execute(backend, &(quotient, b_if), channel)?;

            let tmp_if = Multiplication.execute(backend, &(c_crt, tmp), channel)?;
            a = Subtraction.execute(backend, &(a, tmp_if), channel)?;
        }

        Ok(quotient)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::arithmetic::Division,
        dummy::{Dummy, DummyVal},
        util::{RngExt, product},
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn division() {
        let mut rng = thread_rng();

        for _ in 0..2 {
            let qs = rng.gen_usable_factors();
            let q = product(&qs);
            let q_ = product(&qs[..qs.len() - 1]);
            let x = rng.r#gen::<u128>() % q_;
            let y = rng.r#gen::<u128>() % q_;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let z = Dummy::eval(&Division, &(x_input, y_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, x / y);
        }
    }
}

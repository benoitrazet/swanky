use crate::{
    BinaryBundle, FancyBinary,
    circuit::Circuit,
    circuits::binary::{BinaryEquality, BinaryMultiplex, BinarySubtraction, Mux},
};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given [`BinaryBundle`]s `a` and `b`, output `GCD(a, b)`.
pub struct Gcd {
    upper_bound: usize,
}

impl Gcd {
    /// Create a new [`Gcd`] circuit using a fixed upper bound.
    ///
    /// Since the circuit needs to be oblivious, we cannot terminate the GCD
    /// algorithm by conditioning on the values of `a` or `b` as is the case in
    /// the "standard" version of GCD. Instead, we rely on an upper bound on the
    /// number of iterations we know the algorithm will terminate by. The
    /// Euclidean algorithm based on subtractions will take no more than `N` steps
    /// where `N` is the larger of the two numbers we are computing the GCD for.
    pub fn new(upper_bound: usize) -> Self {
        Self { upper_bound }
    }
}

impl<F: FancyBinary> Circuit<F> for Gcd {
    type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (mut a, mut b) = inputs.clone();
        let zero = backend.constant(0, 2, channel)?;

        for _ in 0..self.upper_bound {
            // Since the circuit is non-branching, we don't know whether `a > b`
            // and cannot branch computation based on that result of that
            // conditional. Instead, we need to perform the computation that
            // occurs for all cases of the predict "is a > b ?", i.e. (1) `a >
            // b`, and (2) `b > a`. We consider the case where `a == b`
            // separately since that is the case where we stop updating our
            // variables and find the result of the computation `gcd(a,b)`.

            // Compute `a := a - b` and check for an underflow that will help
            // determine if `a > b`.
            let (r_1, mut underflow_r_1) =
                BinarySubtraction.execute(backend, &(a.to_owned(), b.to_owned()), channel)?;
            // Compute `b := b - a` and check for an underflow that will help
            // determine if `b > a`.
            let (r_2, mut underflow_r_2) =
                BinarySubtraction.execute(backend, &(b.to_owned(), a.to_owned()), channel)?;

            let is_equal =
                BinaryEquality.execute(backend, &(a.to_owned(), b.to_owned()), channel)?;

            // The `underflow` bits act as dual purpose multiplexing bits:
            // (1) If a > b then underflow_r_1 = 1 and underflow_r_2 = 0
            // (2) If b > a then underflow_r_1 = 0 and underflow_r_2 = 1
            // (3) If a == b then underflow_r_1 = underflow_r_2 = 0
            underflow_r_1 = Mux.execute(
                backend,
                &(is_equal.clone(), underflow_r_1, zero.clone()),
                channel,
            )?;
            underflow_r_2 =
                Mux.execute(backend, &(is_equal, underflow_r_2, zero.clone()), channel)?;

            // Using the `underflow` bits we multiplex in the following way:
            // (1) If a > b, a := a - b and b := b
            // (2) If b > a, a := a  and b := b - a
            // (3) If a == b, a := a and b := b
            a = BinaryMultiplex.execute(backend, &(underflow_r_1, a, r_1), channel)?;
            b = BinaryMultiplex.execute(backend, &(underflow_r_2, b, r_2), channel)?;
        }

        Ok(a)
    }
}

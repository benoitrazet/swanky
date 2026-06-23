use crate::{
    BinaryBundle,
    circuits::binary::{BinaryConstant, BinaryEquality, BinaryMultiplex, PairwiseXor},
};
use fancy_traits::{Circuit, CircuitInputMapper, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Circuit for running linear ORAM.
///
/// For a vector of [`BinaryBundle`]s and a single [`BinaryBundle`] query,
/// output either 0 if no match was found, or the index that matches the query.
/// Each [`BinaryBundle`] contains `N` bits.
pub struct LinearOram<const N: usize> {
    size: usize,
}

impl<const N: usize> LinearOram<N> {
    /// Create a new [`LinearOram`] containing `size` elements.
    pub fn new(size: usize) -> Self {
        Self { size }
    }
}

impl<F: FancyBinary, const N: usize> Circuit<F> for LinearOram<N> {
    type Input = (Vec<BinaryBundle<F::Item>>, BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (ram, query) = inputs;
        let zero_bit = backend.constant(0, 2, channel)?;
        let one_bit = backend.constant(1, 2, channel)?;

        let zero =
            BinaryConstant::new_with_constants(0, N, Some(zero_bit.clone()), Some(one_bit.clone()))
                .execute(backend, (), channel)?;

        // Traverse the RAM one element at a time, and multiplex the result
        // based on whether the query matches the current index.
        let mut result = zero.clone();
        for (i, item) in ram.iter().enumerate() {
            let index = BinaryConstant::new_with_constants(
                i as u128,
                N,
                Some(zero_bit.clone()),
                Some(one_bit.clone()),
            )
            .execute(backend, (), channel)?;
            let is_equal = BinaryEquality::new().execute(backend, (&query, &index), channel)?;
            let mux = BinaryMultiplex::new().execute(backend, (is_equal, &zero, item), channel)?;
            // Every `mux` but one will be zero, so we can use `PairwiseXor`
            // instead of `BinaryAddition`.
            let xor =
                PairwiseXor::new().execute(backend, (result.wires(), mux.wires()), channel)?;
            result = BinaryBundle::new(xor);
        }
        Ok(result)
    }
}

impl<F: FancyBinary, const N: usize> CircuitInputMapper<F> for LinearOram<N> {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), (self.size + 1) * N);
        let (ram_bits, query_bits) = inputs.split_at(self.size * N);

        let ram: Vec<BinaryBundle<F::Item>> = ram_bits
            .chunks(N)
            .map(|chunk| BinaryBundle::new(chunk.to_vec()))
            .collect();
        let query = BinaryBundle::new(query_bits.to_vec());

        (ram, query)
    }

    fn ninputs(&self) -> usize {
        (self.size + 1) * N
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

#[cfg(test)]
pub mod test {
    use crate::{BinaryBundle, circuits::LinearOram};
    use fancy_plaintext::{Dummy, DummyVal};
    use rand::Rng;

    #[test]
    fn linear_oram() {
        const N: usize = 128;
        let mut rng = rand::thread_rng();
        let ram_size = 10;
        let c = LinearOram::<N>::new(ram_size);

        for _ in 0..16 {
            let ram: Vec<u128> = (0..ram_size).map(|_| rng.r#gen::<u128>()).collect();
            let index = rng.r#gen::<usize>() % ram_size;

            let ram_input: Vec<BinaryBundle<DummyVal>> = ram
                .iter()
                .map(|&val| BinaryBundle::from((val, N)))
                .collect();
            let query_input = BinaryBundle::from((index as u128, N));
            let output = Dummy::eval(&c, (ram_input, query_input)).unwrap();
            let result: u128 = output.into();
            assert_eq!(result, ram[index]);
        }
    }
}

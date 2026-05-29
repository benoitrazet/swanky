use crate::{
    BinaryBundle, BinaryGadgets, FancyBinary, circuit::Circuit, circuits::binary::BinaryEquality,
};

/// Circuit for running linear ORAM.
///
/// For a vector of [`BinaryBundle`]s and a single [`BinaryBundle`] query,
/// output either 0 if no match was found, or the index that matches.
pub struct LinearOram<const N: usize>;

impl<F: FancyBinary, const N: usize> Circuit<F> for LinearOram<N> {
    type Input = (Vec<BinaryBundle<F::Item>>, BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut swanky_channel::Channel,
    ) -> swanky_error::Result<Self::Output> {
        let (ram, index) = inputs;

        let mut result = backend.bin_constant_bundle(0, N, channel)?;
        let zero = backend.bin_constant_bundle(0, N, channel)?;

        // We traverse the garbler's RAM one element at a time, and multiplex
        // the result based on whether the evaluator's query matches the current
        // index.
        for (i, item) in ram.iter().enumerate() {
            // The current index is turned into a binary constant bundle.
            let current_index = backend.bin_constant_bundle(i as u128, N, channel)?;
            // We check if the evaluator's query matches the current index obliviously.
            let mux_bit =
                BinaryEquality.execute(backend, &(index.to_owned(), current_index), channel)?;
            // We use the result of the prior equality check to multiplex by either adding 0 to
            // the result of the computation and keeping it as is, or adding RAM[i] to it
            // and updating it. The evaluator's query can only correspond to a single index.
            let mux = backend.bin_multiplex(&mux_bit, &zero, item, channel)?;
            result = backend.bin_addition_no_carry(&result, &mux, channel)?;
        }

        Ok(result)
    }
}

pub mod test {
    use super::*;
    use crate::circuit::CircuitExecutor;

    /// Circuit for testing [`LinearOram`].
    pub struct TestLinearOram<const N: usize> {
        /// The size of the RAM.
        pub ram_size: usize,
    }

    impl<F: FancyBinary, const N: usize> Circuit<F> for TestLinearOram<N> {
        type Input = <LinearOram<N> as Circuit<F>>::Input;
        type Output = <LinearOram<N> as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: &Self::Input,
            channel: &mut swanky_channel::Channel,
        ) -> swanky_error::Result<Self::Output> {
            (LinearOram::<N>).execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinary, const N: usize> CircuitExecutor<F> for TestLinearOram<N> {
        fn map(&self, inputs: Vec<<F as crate::Fancy>::Item>) -> Self::Input {
            // inputs = [ram[0] bits, ram[1] bits, ..., ram[ram_size-1] bits, query bits]
            assert_eq!(inputs.len(), (self.ram_size + 1) * N);
            let (ram_bits, query_bits) = inputs.split_at(self.ram_size * N);

            let ram: Vec<BinaryBundle<F::Item>> = ram_bits
                .chunks(N)
                .map(|chunk| BinaryBundle::new(chunk.to_vec()))
                .collect();
            let query = BinaryBundle::new(query_bits.to_vec());

            (ram, query)
        }

        fn ninputs(&self) -> usize {
            (self.ram_size + 1) * N
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn linear_oram() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        const N: usize = 128;
        let mut rng = rand::thread_rng();
        let ram_size = 10;
        let c = TestLinearOram::<N> { ram_size };

        for _ in 0..16 {
            let ram: Vec<u128> = (0..ram_size).map(|_| rng.r#gen::<u128>()).collect();
            let index = rng.r#gen::<usize>() % ram_size;

            let ram_input: Vec<BinaryBundle<DummyVal>> =
                ram.iter().map(|&val| DummyVal::to_binary(val, N)).collect();
            let query_input = DummyVal::to_binary(index as u128, N);
            let output = Dummy::eval(&c, &(ram_input, query_input)).unwrap();
            let result = DummyVal::from_binary(&output);
            assert_eq!(result, ram[index]);
        }
    }
}

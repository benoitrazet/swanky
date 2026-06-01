//! SHA circuits.

use crate::{
    FancyBinary,
    circuit::{BinaryCircuit, Circuit},
};
use std::io::Cursor;
use swanky_channel::Channel;
use swanky_error::Result;

/// Circuit for the SHA-256 compression function.
pub struct Sha256CompressionFunction(BinaryCircuit);

impl Sha256CompressionFunction {
    /// Create a new [`Sha256CompressionFunction`] circuit.
    ///
    /// # Performance Note!
    /// This involves parsing a Bristol Format file, and thus is not cheap!
    /// Hence, it is best to reuse this circuit if possible versus calling
    /// [`Sha256CompressionFunction::new`] every time this circuit is needed.
    pub fn new() -> Self {
        let circuit = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/sha-256.txt"),
        ))
        .expect("`sha-256.txt` file should always parse correctly");
        Self(circuit)
    }
}

impl Default for Sha256CompressionFunction {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FancyBinary> Circuit<F> for Sha256CompressionFunction {
    type Input = ([F::Item; 256], [F::Item; 256]);
    type Output = [F::Item; 256];

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut combined = inputs.0.to_vec();
        combined.extend_from_slice(&inputs.1);
        let output = self.0.execute(backend, &combined, channel)?;
        Ok(output
            .try_into()
            .expect("SHA-256 compression function output should always be 256 elements"))
    }
}

/// Circuits for testing SHA.
pub mod test {
    use super::*;
    use crate::circuit::CircuitExecutor;
    #[cfg(test)]
    use crate::dummy::{Dummy, DummyVal};

    /// Circuit for testing [`Sha256CompressionFunction`].
    pub struct TestSha256CompressionFunction(Sha256CompressionFunction);

    impl TestSha256CompressionFunction {
        /// Create a new [`TestSha256CompressionFunction`] circuit.
        pub fn new() -> Self {
            Self(Sha256CompressionFunction::new())
        }
    }

    impl Default for TestSha256CompressionFunction {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<F: FancyBinary> Circuit<F> for TestSha256CompressionFunction {
        type Input = <Sha256CompressionFunction as Circuit<F>>::Input;
        type Output = <Sha256CompressionFunction as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: &Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            self.0.execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinary> CircuitExecutor<F> for TestSha256CompressionFunction {
        fn map(&self, inputs: Vec<<F as crate::Fancy>::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 512);
            let block = inputs[..256]
                .to_vec()
                .try_into()
                .expect("Block should contain 256 elements");
            let chain = inputs[256..]
                .to_vec()
                .try_into()
                .expect("Chaining value should contain 256 elements");
            (block, chain)
        }

        fn ninputs(&self) -> usize {
            512
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[cfg(test)]
    fn string_to_bool_vec(str: &str) -> Vec<DummyVal> {
        str.chars()
            .map(|c| match c {
                '0' => DummyVal::new_bool(false),
                '1' => DummyVal::new_bool(true),
                _ => panic!("Unexpected character in boolean string"),
            })
            .collect()
    }

    #[test]
    fn sha256_compression_function() {
        // Uses the test vectors found here:
        // <https://nigelsmart.github.io/MPC-Circuits/sha-256-test.txt>.

        let sha256 = TestSha256CompressionFunction::new();

        let block = [DummyVal::new_bool(false); 256];
        let chain = [DummyVal::new_bool(false); 256];
        let output = Dummy::eval(&sha256, &(block, chain)).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1101101001010110100110001011111000010111101110011011010001101001011000100011001101010111100110010111011110011111101111101100101010001100111001011101010010010001110000001101001001100010010000111011101011111110111110011110101000011000001101111010100111011000"
        );

        let block = string_to_bool_vec(
            "0000000000000001000000100000001100000100000001010000011000000111000010000000100100001010000010110000110000001101000011100000111100010000000100010001001000010011000101000001010100010110000101110001100000011001000110100001101100011100000111010001111000011111",
        ).try_into().unwrap();
        let chain = string_to_bool_vec(
            "0010000000100001001000100010001100100100001001010010011000100111001010000010100100101010001010110010110000101101001011100010111100110000001100010011001000110011001101000011010100110110001101110011100000111001001110100011101100111100001111010011111000111111",
        ).try_into().unwrap();
        let output = Dummy::eval(&sha256, &(block, chain)).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1111110010011001101000101101111110001000111101000010101001111010011110111011100111010001100000000011001111001101110001101010001000000010010101100111010101011111100111010101101110011010010100000100010010101001110011000011000101011010101111101000010010100111"
        );

        let block = [DummyVal::new_bool(true); 256];
        let chain = [DummyVal::new_bool(true); 256];
        let output = Dummy::eval(&sha256, &(block, chain)).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1110111100001100011101001000110111110100110110100101000010101000110101101100010000111100000000010011111011011100001111001110011101101100100111011001111110101001101000010100010110001010110111100101011011101011100001101100000010100110010001001001001011010010"
        );

        let block = string_to_bool_vec(
            "0010010000111111011010101000100010000101101000110000100011010011000100110001100110001010001011100000001101110000011100110100010010100100000010010011100000100010001010011001111100110001110100000000100000101110111110101001100011101100010011100110110010001001",
        ).try_into().unwrap();
        let chain = string_to_bool_vec(
            "0100010100101000001000011110011000111000110100000001001101110111101111100101010001100110110011110011010011101001000011000110110011000000101011000010100110110111110010010111110001010000110111010011111110000100110101011011010110110101010001110000100100010111",
        ).try_into().unwrap();
        let output = Dummy::eval(&sha256, &(block, chain)).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1100111100001010111001001110101101100111110100111000111111111110101110010100000001101000100110000100101100100010101010111101111001001110100100101011110001010100100011010001010001011000010111100100100011011100101010001000100000101101011110110000100111001110"
        );
    }
}

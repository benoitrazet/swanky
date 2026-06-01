//! SHA circuits.

use crate::{
    FancyBinary,
    circuit::{BinaryCircuit, Circuit},
};
use std::io::Cursor;
use swanky_channel::Channel;
use swanky_error::{Error, ErrorKind, Result};

/// Circuit for the SHA-256 compression function, where the input chaining
/// values are fixed to the SHA-256 IV.
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
    type Input = [F::Item; 512];
    type Output = [F::Item; 256];

    fn execute(
        &self,
        backend: &mut F,
        input: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let output = self.0.execute(backend, &input.to_vec(), channel)?;
        Ok(output
            .try_into()
            .expect("SHA-256 compression function output should always be 256 elements"))
    }
}

/// Circuit for a single block SHA-256 hash function.
///
/// # Limitations
/// This implementation can only handle messages up to 447 bits in length, as it
/// uses a single-block SHA-256 compression function that has the SHA-256 IV
/// hardcoded. Messages longer than 447 bits would require multiple blocks and
/// chaining values from previous blocks, which the underlying circuit does not
/// support.
pub struct Sha256SingleBlock(Sha256CompressionFunction);

impl Sha256SingleBlock {
    /// Create a new [`Sha256SingleBlock`] circuit.
    ///
    /// # Performance Note!
    /// This involves parsing a Bristol Format file, and thus is not cheap!
    /// Hence, it is best to reuse this circuit if possible versus calling
    /// [`Sha256SingleBlock::new`] every time this circuit is needed.
    pub fn new() -> Self {
        Self(Sha256CompressionFunction::new())
    }
}

impl Default for Sha256SingleBlock {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FancyBinary> Circuit<F> for Sha256SingleBlock {
    type Input = Vec<F::Item>;
    type Output = [F::Item; 256];

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let message_len = inputs.len();

        // Check that the message fits in a single block after padding.
        // A 512-bit block contains: message + '1' bit + padding zeros + 64-bit length.
        // So we need: `message_len + 1 + padding + 64 ≤ 512`.
        // Which means: `message_len ≤ 447`.
        if message_len > 447 {
            return Err(Error::new(
                ErrorKind::UnsupportedError,
                "Message too long for single-block SHA-256 (max 447 bits)",
                None,
            ));
        }

        // Pad the input message to exactly 512 bits
        let mut padded = inputs.clone();

        // Append a single '1' bit
        padded.push(backend.constant(1, 2, channel)?);

        // Calculate how many '0' bits we need to reach 448 (= 512 - 64) bits.
        let zeros_needed = 448 - padded.len();
        for _ in 0..zeros_needed {
            padded.push(backend.constant(0, 2, channel)?);
        }

        // Append the original message length as a 64-bit big-endian integer.
        for i in (0..64).rev() {
            let bit = ((message_len >> i) & 1) as u16;
            padded.push(backend.constant(bit, 2, channel)?);
        }

        // padded should now be exactly 512 bits
        assert_eq!(padded.len(), 512);

        let padded = padded.try_into().unwrap();

        self.0.execute(backend, &padded, channel)
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
            inputs.try_into().unwrap() // This `unwrap` will never fail: we check in the assert above that the input is of the right length.
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

    /// Circuit for testing [`Sha256SingleBlock`].
    pub struct TestSha256(usize, Sha256SingleBlock);

    impl TestSha256 {
        /// Create a new [`TestSha256`] circuit.
        pub fn new(length: usize) -> Self {
            assert!(length <= 447);
            Self(length, Sha256SingleBlock::new())
        }
    }

    impl<F: FancyBinary> Circuit<F> for TestSha256 {
        type Input = <Sha256SingleBlock as Circuit<F>>::Input;
        type Output = <Sha256SingleBlock as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: &Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            self.1.execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinary> CircuitExecutor<F> for TestSha256 {
        fn map(&self, inputs: Vec<<F as crate::Fancy>::Item>) -> Self::Input {
            inputs
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn sha256_compression_function() {
        // Uses the test vectors found here:
        // <https://nigelsmart.github.io/MPC-Circuits/sha-256-test.txt>.

        let sha256 = TestSha256CompressionFunction::new();

        let block = [DummyVal::new_bool(false); 512];
        let output = Dummy::eval(&sha256, &block).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1101101001010110100110001011111000010111101110011011010001101001011000100011001101010111100110010111011110011111101111101100101010001100111001011101010010010001110000001101001001100010010000111011101011111110111110011110101000011000001101111010100111011000"
        );

        let block = string_to_bool_vec(
            "00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111000100000001000100010010000100110001010000010101000101100001011100011000000110010001101000011011000111000001110100011110000111110010000000100001001000100010001100100100001001010010011000100111001010000010100100101010001010110010110000101101001011100010111100110000001100010011001000110011001101000011010100110110001101110011100000111001001110100011101100111100001111010011111000111111",
        ).try_into().unwrap();
        let output = Dummy::eval(&sha256, &block).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1111110010011001101000101101111110001000111101000010101001111010011110111011100111010001100000000011001111001101110001101010001000000010010101100111010101011111100111010101101110011010010100000100010010101001110011000011000101011010101111101000010010100111"
        );

        let block = [DummyVal::new_bool(true); 512];
        let output = Dummy::eval(&sha256, &block).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1110111100001100011101001000110111110100110110100101000010101000110101101100010000111100000000010011111011011100001111001110011101101100100111011001111110101001101000010100010110001010110111100101011011101011100001101100000010100110010001001001001011010010"
        );

        let block = string_to_bool_vec(
            "00100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000000011011100000111001101000100101001000000100100111000001000100010100110011111001100011101000000001000001011101111101010011000111011000100111001101100100010010100010100101000001000011110011000111000110100000001001101110111101111100101010001100110110011110011010011101001000011000110110011000000101011000010100110110111110010010111110001010000110111010011111110000100110101011011010110110101010001110000100100010111",
        ).try_into().unwrap();
        let output = Dummy::eval(&sha256, &block).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1100111100001010111001001110101101100111110100111000111111111110101110010100000001101000100110000100101100100010101010111101111001001110100100101011110001010100100011010001010001011000010111100100100011011100101010001000100000101101011110110000100111001110"
        );
    }

    #[test]
    fn sha256_empty_string() {
        // Test SHA-256 with empty string input.
        // Expected output: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

        let sha256 = TestSha256::new(0);
        let input = vec![];
        let output = Dummy::eval(&sha256, &input).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1110001110110000110001000100001010011000111111000001110000010100100110101111101111110100110010001001100101101111101110010010010000100111101011100100000111100100011001001001101110010011010011001010010010010101100110010001101101111000010100101011100001010101"
        );
    }

    #[test]
    fn sha256_abc() {
        // Test SHA-256 with "abc" input.
        // Expected output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

        let sha256 = TestSha256::new(8 * 3);

        // "abc" in binary (ASCII encoding)
        // 'a' = 0x61 = 01100001
        // 'b' = 0x62 = 01100010
        // 'c' = 0x63 = 01100011
        let input = string_to_bool_vec("011000010110001001100011");
        let output = Dummy::eval(&sha256, &input).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "1011101001111000000101101011111110001111000000011100111111101010010000010100000101000000110111100101110110101110001000100010001110110000000000110110000110100011100101100001011101111010100111001011010000010000111111110110000111110010000000000001010110101101"
        );
    }
}

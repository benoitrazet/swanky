//! DSL for creating circuits compatible with fancy-garbling in the old-fashioned way,
//! where you create a circuit for a computation then garble it.

use crate::{
    dummy::{Dummy, DummyVal},
    fancy::Fancy,
    informer::Informer,
};
use swanky_channel::Channel;
use swanky_error::Result;

mod binary;
pub use binary::{BinaryCircuit, BinaryGate};

/// Trait for executing computations directly over a [`Fancy`] object.
///
/// # Example
/// Below is a simple example of computing an add gate over an arbitrary
/// modulus. The computation is defined in `execute` by directly calling
/// operations on the underlying [`Fancy`] backend. We also need to track how
/// many inputs the computation takes, and the moduli of those inputs; these are
/// given in the `ninputs` and `modulus` methods, respectively.
/// ```
/// # use fancy_garbling::{FancyArithmetic, circuit::CircuitExecutor};
/// # use swanky_channel::Channel;
/// # use swanky_error::Result;
/// struct AddCircuit(u16);
/// impl<F: FancyArithmetic> CircuitExecutor<F> for AddCircuit {
///     fn execute(
///         &self,
///         backend: &mut F,
///         inputs: &[F::Item],
///         channel: &mut Channel,
///     ) -> Result<Vec<F::Item>> {
///         let output = backend.add(&inputs[0], &inputs[1]);
///         Ok(vec![output])
///     }
///
///     fn ninputs(&self) -> usize {
///         2
///     }
///
///     fn modulus(&self, _: usize) -> u16 {
///         2
///     }
/// }
/// ```
pub trait CircuitExecutor<F: Fancy> {
    /// Execute a circuit on a given [`Fancy`] backend using the provided inputs.
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> Result<Vec<F::Item>>;
    /// The number of inputs to provide to [`CircuitExecutor::execute`].
    fn ninputs(&self) -> usize;
    /// The modulus for input `i`.
    fn modulus(&self, i: usize) -> u16;
}

/// Trait to display circuit evaluation costs
///
/// Blanket implementation available for all circuits
/// that can be evaluated with an `Informer`
pub trait CircuitInfo {
    /// Print circuit info
    fn print_info(&self) -> swanky_error::Result<()>;
}

impl<C: CircuitExecutor<Informer<Dummy>>> CircuitInfo for C {
    fn print_info(&self) -> swanky_error::Result<()> {
        let mut informer = crate::informer::Informer::new(Dummy::new());

        // encode inputs as InformerVals
        let inputs = Channel::with(std::io::empty(), |channel| {
            (0..self.ninputs())
                .map(|i| informer.encode(0, self.modulus(i), channel))
                .collect::<swanky_error::Result<Vec<DummyVal>>>()
        })?;

        Channel::with(std::io::empty(), |c| {
            self.execute(&mut informer, &inputs, c)
        })?;
        println!("{}", informer.stats());
        Ok(())
    }
}

pub mod circuits {
    //! A collection of test circuits.

    use crate::{
        ArithmeticBundleGadgets, ArithmeticProjBundleGadgets, BinaryBundle, BinaryGadgets, Bundle,
        BundleGadgets, CrtBundle, CrtGadgets, CrtProjGadgets, Fancy, FancyArithmetic, FancyBinary,
        FancyProj, circuit::CircuitExecutor,
    };
    use swanky_channel::Channel;
    use swanky_error::Result;

    /// Circuit for testing [`FancyBinary::and_many`].
    pub struct TestAndGateFanN(pub usize);
    impl<F: FancyBinary> CircuitExecutor<F> for TestAndGateFanN {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let output = backend.and_many(inputs, channel)?;
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`FancyBinary::or_many`].
    pub struct TestOrGateFanN(pub usize);
    impl<F: FancyBinary> CircuitExecutor<F> for TestOrGateFanN {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let output = backend.or_many(inputs, channel)?;
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`FancyBinary::xor_many`].
    pub struct TestXorGateFanN(pub usize);
    impl<F: FancyBinary> CircuitExecutor<F> for TestXorGateFanN {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let output = backend.xor_many(inputs);
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`Fancy::constant`].
    pub struct TestBinaryConstant();
    impl<F: Fancy> CircuitExecutor<F> for TestBinaryConstant {
        fn execute(
            &self,
            backend: &mut F,
            _inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let outputs = vec![
                backend.constant(0, 2, channel)?,
                backend.constant(1, 2, channel)?,
            ];
            backend.outputs(&outputs, channel)?;
            Ok(outputs)
        }

        fn ninputs(&self) -> usize {
            0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }
    /// Circuit for testing [`FancyArithmetic::add`].
    pub struct TestAddition(pub u16);
    impl<F: FancyArithmetic> CircuitExecutor<F> for TestAddition {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            _: &mut Channel,
        ) -> swanky_error::Result<Vec<F::Item>> {
            let output = backend.add(&inputs[0], &inputs[1]);
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`FancyArithmetic::add_many`].
    pub struct TestAddMany(pub u16, pub usize);
    impl<F: FancyArithmetic> CircuitExecutor<F> for TestAddMany {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let output = backend.add_many(inputs);
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            self.1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`FancyArithmetic::sub`].
    pub struct TestSubtraction(pub u16);
    impl<F: FancyArithmetic> CircuitExecutor<F> for TestSubtraction {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            _: &mut Channel,
        ) -> swanky_error::Result<Vec<F::Item>> {
            let z = backend.sub(&inputs[0], &inputs[1]);
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`FancyBinary::and`].
    pub struct TestAndGate;
    impl<F: FancyBinary> CircuitExecutor<F> for TestAndGate {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let output = backend.and(&inputs[0], &inputs[1], channel)?;
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`FancyArithmetic::mul`].
    pub struct TestMulGate(pub u16);
    impl<F: FancyArithmetic> CircuitExecutor<F> for TestMulGate {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let output = backend.mul(&inputs[0], &inputs[1], channel)?;
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`FancyArithmetic::mul`] using two different moduli
    /// for the inputs.
    pub struct TestMulGateUnequalMods(pub [u16; 2]);
    impl<F: FancyArithmetic> CircuitExecutor<F> for TestMulGateUnequalMods {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let output = backend.mul(&inputs[0], &inputs[1], channel)?;
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }

    /// Circuit for testing [`FancyArithmetic::cmul`].
    pub struct TestCmul(pub u16, pub u16);
    impl<F: FancyArithmetic> CircuitExecutor<F> for TestCmul {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let output = backend.cmul(&inputs[0], self.1);
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`FancyProj::proj`].
    pub struct TestProj(pub u16);
    impl<F: FancyProj> CircuitExecutor<F> for TestProj {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let tab = (0..self.0).map(|i| (i + 1) % self.0).collect();
            let output = backend.proj(&inputs[0], self.0, Some(tab), channel)?;
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`FancyProj::proj`] using a custom truth table.
    pub struct TestProjRand(pub u16, pub Vec<u16>);
    impl<F: FancyProj> CircuitExecutor<F> for TestProjRand {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let output = backend.proj(&inputs[0], self.0, Some(self.1.clone()), channel)?;
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`FancyProj::mod_change`].
    pub struct TestModChange(pub u16, pub u16);
    impl<F: FancyProj> CircuitExecutor<F> for TestModChange {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let y = backend.mod_change(&inputs[0], self.1, channel)?;
            let z = backend.mod_change(&y, self.0, channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`FancyProj::mod_change`] followed by
    /// [`FancyArithmetic::add_many`].
    pub struct TestAddManyModChange(pub usize);
    impl<F: FancyProj + FancyArithmetic> CircuitExecutor<F> for TestAddManyModChange {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let wires = inputs
                .iter()
                .map(|x| backend.mod_change(x, self.0 as u16 + 1, channel))
                .collect::<Result<Vec<_>>>()?;
            let output = backend.add_many(&wires);
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing constant gates.
    pub struct TestConstants(pub u16, pub u16);
    impl<F: FancyArithmetic> CircuitExecutor<F> for TestConstants {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let constant = backend.constant(self.1, self.0, channel)?;
            let output = backend.add(&inputs[0], &constant);
            backend.output(&output, channel)?;
            Ok(vec![output])
        }

        fn ninputs(&self) -> usize {
            1
        }

        fn modulus(&self, _: usize) -> u16 {
            self.0
        }
    }

    /// Circuit for testing [`CrtBundle`]s.
    pub struct TestBundleInputOutput(pub Vec<u16>);
    impl<F: BundleGadgets> CircuitExecutor<F> for TestBundleInputOutput {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let output = CrtBundle::new(inputs.to_vec());
            backend.output_bundle(&output, channel)?;
            Ok(output.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len()
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }

    /// Circuit for testing [`CrtGadgets::crt_add`].
    pub struct TestCrtAddition(pub Vec<u16>);
    impl<F: CrtGadgets> CircuitExecutor<F> for TestCrtAddition {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let x = CrtBundle::new(inputs[..self.0.len()].to_vec());
            let y = CrtBundle::new(inputs[self.0.len()..].to_vec());
            let z = backend.crt_add(&x, &y);
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len() * 2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`CrtGadgets::crt_sub`].
    pub struct TestCrtSubtraction(pub Vec<u16>);
    impl<F: CrtGadgets> CircuitExecutor<F> for TestCrtSubtraction {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let x = CrtBundle::new(inputs[..self.0.len()].to_vec());
            let y = CrtBundle::new(inputs[self.0.len()..].to_vec());
            let z = backend.crt_sub(&x, &y);
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len() * 2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`CrtGadgets::crt_cmul`].
    pub struct TestCrtCmul(pub Vec<u16>, pub u128);
    impl<F: CrtGadgets> CircuitExecutor<F> for TestCrtCmul {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let x = CrtBundle::new(inputs.to_vec());
            let z = backend.crt_cmul(&x, self.1);
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len()
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }

    /// Circuit for testing [`ArithmeticBundleGadgets::mul_bundles`].
    pub struct TestCrtMultiplication(pub Vec<u16>);
    impl<F: ArithmeticBundleGadgets> CircuitExecutor<F> for TestCrtMultiplication {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let x = CrtBundle::new(inputs[..self.0.len()].to_vec());
            let y = CrtBundle::new(inputs[self.0.len()..].to_vec());
            let z = backend.mul_bundles(&x, &y, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len() * 2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`ArithmeticBundleGadgets::mask`].
    pub struct TestMask(pub Vec<u16>);
    impl<F: ArithmeticBundleGadgets> CircuitExecutor<F> for TestMask {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let b = &inputs[0];
            let x = CrtBundle::new(inputs[1..self.0.len() + 1].to_vec());
            let z = backend.mask(b, &x, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len() + 1
        }

        fn modulus(&self, i: usize) -> u16 {
            if i == 0 { 2 } else { self.0[i - 1] }
        }
    }

    /// Circuit for testing [`CrtProjGadgets::crt_cexp`].
    pub struct TestCrtCexp(pub Vec<u16>, pub u16);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestCrtCexp {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let x = CrtBundle::new(inputs.to_vec());
            let z = backend.crt_cexp(&x, self.1, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len()
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }

    /// Circuit for testing [`CrtProjGadgets::crt_div`].
    pub struct TestCrtDivision(pub Vec<u16>);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestCrtDivision {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let x = CrtBundle::new(inputs[..self.0.len()].to_vec());
            let y = CrtBundle::new(inputs[self.0.len()..].to_vec());
            let z = backend.crt_div(&x, &y, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len() * 2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`CrtProjGadgets::crt_rem`].
    pub struct TestCrtRemainder(pub Vec<u16>, pub u16);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestCrtRemainder {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let x = CrtBundle::new(inputs.to_vec());
            let z = backend.crt_rem(&x, self.1, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len()
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }

    /// Circuit for testing [`ArithmeticProjBundleGadgets::eq_bundles`].
    pub struct TestEqBundles(pub Vec<u16>);
    impl<F: ArithmeticProjBundleGadgets> CircuitExecutor<F> for TestEqBundles {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[F::Item],
            channel: &mut Channel,
        ) -> Result<Vec<F::Item>> {
            let x = CrtBundle::new(inputs[..self.0.len()].to_vec());
            let y = CrtBundle::new(inputs[self.0.len()..].to_vec());
            let z = backend.eq_bundles(&x, &y, channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            self.0.len() * 2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing multiple CRT operations.
    pub struct TestComplexGadget(pub Vec<u16>, pub usize);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestComplexGadget {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let inputs = inputs
                .chunks_exact(self.0.len())
                .map(|x| CrtBundle::new(x.to_vec()))
                .collect::<Vec<_>>();
            let mut outputs = Vec::with_capacity(inputs.len());
            for x in inputs.iter() {
                let c = backend.crt_constant_bundle(1, x.composite_modulus(), channel)?;
                let y = backend.crt_mul(x, &c, channel)?;
                let z = backend.crt_relu(&y, "100%", None, channel)?;
                outputs.push(z);
            }
            backend.crt_outputs(&outputs, channel)?;
            Ok(outputs
                .iter()
                .map(|out| out.wires().to_vec())
                .collect::<Vec<_>>()
                .concat())
        }

        fn ninputs(&self) -> usize {
            self.1
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`ArithmeticProjBundleGadgets::mixed_radix_addition`].
    pub struct TestMixedRadixAddition(pub Vec<u16>, pub usize);
    impl<F: ArithmeticProjBundleGadgets> CircuitExecutor<F> for TestMixedRadixAddition {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let xs = inputs
                .chunks_exact(self.0.len())
                .map(|v| Bundle::new(v.to_vec()))
                .collect::<Vec<_>>();
            let z = backend.mixed_radix_addition(&xs, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.1 * self.0.len()
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`ArithmeticProjBundleGadgets::mixed_radix_addition_msb_only`].
    pub struct TestMixedRadixAdditionMSBOnly(pub Vec<u16>, pub usize);
    impl<F: ArithmeticProjBundleGadgets> CircuitExecutor<F> for TestMixedRadixAdditionMSBOnly {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let xs = inputs
                .chunks_exact(self.0.len())
                .map(|v| Bundle::new(v.to_vec()))
                .collect::<Vec<_>>();
            let z = backend.mixed_radix_addition_msb_only(&xs, channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            self.0.len() * self.1
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`CrtProjGadgets::crt_relu`].
    pub struct TestRelu(pub Vec<u16>);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestRelu {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = CrtBundle::new(inputs.to_vec());
            let z = backend.crt_relu(&x, "100%", None, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len()
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }

    /// Circuit for testing [`CrtProjGadgets::crt_sgn`].
    pub struct TestSgn(pub Vec<u16>);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestSgn {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = CrtBundle::new(inputs.to_vec());
            let z = backend.crt_sgn(&x, "100%", None, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len()
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }

    /// Circuit for testing [`CrtProjGadgets::crt_lt`].
    pub struct TestLeq(pub Vec<u16>);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestLeq {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = CrtBundle::new(inputs[..self.0.len()].to_vec());
            let y = CrtBundle::new(inputs[self.0.len()..].to_vec());
            let z = backend.crt_lt(&x, &y, "100%", channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            self.0.len() * 2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`CrtProjGadgets::crt_max`].
    pub struct TestMax(pub Vec<u16>, pub usize);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestMax {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let xs = inputs
                .chunks_exact(self.0.len())
                .map(|v| CrtBundle::new(v.to_vec()))
                .collect::<Vec<_>>();
            let z = backend.crt_max(&xs, "100%", channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len() * self.1
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`BundleGadgets::shift_extend`].
    pub struct TestShiftExtend(pub usize, pub usize);
    impl<F: BundleGadgets> CircuitExecutor<F> for TestShiftExtend {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs.to_vec());
            let z = backend.shift_extend(&x, self.1, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_and`].
    pub struct TestBinaryAnd(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryAnd {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let z = backend.bin_and(&x, &y, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_addition`].
    pub struct TestBinaryAddition(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryAddition {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let (z, carry) = backend.bin_addition(&x, &y, channel)?;
            backend.output(&carry, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok([vec![carry], z.wires().to_vec()].concat())
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_subtraction`].
    pub struct TestBinarySubtraction(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinarySubtraction {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let (z, underflow) = backend.bin_subtraction(&x, &y, channel)?;
            backend.output(&underflow, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok([vec![underflow], z.wires().to_vec()].concat())
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_mul`].
    pub struct TestBinaryMultiplication(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryMultiplication {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let z = backend.bin_mul(&x, &y, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_multiplication_lower_half`].
    pub struct TestBinaryMultiplicationLowerHalf(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryMultiplicationLowerHalf {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let z = backend.bin_multiplication_lower_half(&x, &y, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_div`].
    pub struct TestBinaryDivision(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryDivision {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let z = backend.bin_div(&x, &y, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_lt`].
    pub struct TestBinaryLessThan(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryLessThan {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let z = backend.bin_lt(&x, &y, channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_lt_signed`].
    pub struct TestBinaryLessThanSigned(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryLessThanSigned {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let z = backend.bin_lt_signed(&x, &y, channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_rsa`].
    pub struct TestBinaryArithmeticRightShift(pub usize, pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryArithmeticRightShift {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs.to_vec());
            let z = backend.bin_rsa(&x, self.1);
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_rsl`].
    pub struct TestBinaryLogicalRightShift(pub usize, pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryLogicalRightShift {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs.to_vec());
            let z = backend.bin_rsl(&x, self.1, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_eq_bundles`].
    pub struct TestBinaryEqBundles(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryEqBundles {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs[..self.0].to_vec());
            let y = BinaryBundle::new(inputs[self.0..].to_vec());
            let z = backend.bin_eq_bundles(&x, &y, channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_abs`].
    pub struct TestBinaryAbs(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryAbs {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs.to_vec());
            let z = backend.bin_abs(&x, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_twos_complement`].
    pub struct TestBinaryTwosComplement(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryTwosComplement {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs.to_vec());
            let z = backend.bin_twos_complement(&x, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_demux`].
    pub struct TestBinaryDemux(pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryDemux {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = BinaryBundle::new(inputs.to_vec());
            let output = backend.bin_demux(&x, channel)?;
            backend.outputs(&output, channel)?;
            Ok(output)
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryGadgets::bin_max`].
    pub struct TestBinaryMax(pub usize, pub usize);
    impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryMax {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let xs = inputs
                .chunks_exact(self.0)
                .map(|v| BinaryBundle::new(v.to_vec()))
                .collect::<Vec<_>>();
            let z = backend.bin_max(&xs, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0 * self.1
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`CrtProjGadgets::crt_to_pmr`].
    pub struct TestCrtToPmr(pub Vec<u16>);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestCrtToPmr {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = CrtBundle::new(inputs.to_vec());
            let z = backend.crt_to_pmr(&x, channel)?;
            backend.output_bundle(&z, channel)?;
            Ok(z.wires().to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0.len()
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i]
        }
    }

    /// Circuit for testing [`CrtProjGadgets::pmr_lt`].
    pub struct TestPmrLessThan(pub Vec<u16>);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestPmrLessThan {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = CrtBundle::new(inputs[..self.0.len()].to_vec());
            let y = CrtBundle::new(inputs[self.0.len()..].to_vec());
            let z = backend.pmr_lt(&x, &y, channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            self.0.len() * 2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }

    /// Circuit for testing [`CrtProjGadgets::pmr_geq`].
    pub struct TestPmrGreaterThanOrEqual(pub Vec<u16>);
    impl<F: CrtProjGadgets> CircuitExecutor<F> for TestPmrGreaterThanOrEqual {
        fn execute(
            &self,
            backend: &mut F,
            inputs: &[<F as crate::Fancy>::Item],
            channel: &mut Channel,
        ) -> Result<Vec<<F as crate::Fancy>::Item>> {
            let x = CrtBundle::new(inputs[..self.0.len()].to_vec());
            let y = CrtBundle::new(inputs[self.0.len()..].to_vec());
            let z = backend.pmr_geq(&x, &y, channel)?;
            backend.output(&z, channel)?;
            Ok(vec![z])
        }

        fn ninputs(&self) -> usize {
            self.0.len() * 2
        }

        fn modulus(&self, i: usize) -> u16 {
            self.0[i % self.0.len()]
        }
    }
}

#[cfg(test)]
mod fancy_binary {
    use crate::{circuit::circuits, dummy::Dummy, util::RngExt};
    use rand::thread_rng;

    #[test]
    fn and_gate_fan_n() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 200);
        let c = circuits::TestAndGateFanN(n);

        for _ in 0..16 {
            let inputs = (0..n).map(|_| rng.gen_bool() as u16).collect::<Vec<_>>();
            let expected = inputs.iter().fold(1, |acc, &x| x & acc);
            let output = Dummy::eval(&c, &inputs).unwrap()[0];
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn binary_constant_gates() {
        let c = circuits::TestBinaryConstant();
        let inputs = [0, 0];
        let expected_0 = 0;
        let output_0: u16 = Dummy::eval(&c, &inputs).unwrap()[0];
        assert_eq!(output_0, expected_0);
        let expected_1 = 1;
        let output_1 = Dummy::eval(&c, &inputs).unwrap()[1];
        assert_eq!(output_1, expected_1);
    }

    #[test]
    fn or_gate_fan_n() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 200);
        let c = circuits::TestOrGateFanN(n);

        for _ in 0..16 {
            let inputs = (0..n).map(|_| rng.gen_bool() as u16).collect::<Vec<_>>();
            let expected = inputs.iter().fold(0, |acc, &x| x | acc);
            let output = Dummy::eval(&c, &inputs).unwrap()[0];
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn xor_gate_fan_n() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 200);
        let c = circuits::TestXorGateFanN(n);

        for _ in 0..16 {
            let inputs = (0..n).map(|_| rng.gen_bool() as u16).collect::<Vec<_>>();
            let expected = inputs.iter().fold(0, |acc, &x| x ^ acc);
            let output = Dummy::eval(&c, &inputs).unwrap()[0];
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn binary_half_gate() {
        let mut rng = thread_rng();
        let c = circuits::TestAndGate;

        for _ in 0..16 {
            let x = rng.gen_bool() as u16;
            let y = rng.gen_bool() as u16;
            let output = Dummy::eval(&c, &[x, y]).unwrap()[0];
            assert_eq!(output, x * y % 2);
        }
    }
}

#[cfg(test)]
mod fancy_arithmetic {
    use crate::{circuit::circuits, dummy::Dummy, util::RngExt};
    use rand::thread_rng;

    #[test]
    fn constants() {
        let mut rng = thread_rng();
        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;
        let circ = circuits::TestConstants(q, c);

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let output = Dummy::eval(&circ, &[x]).unwrap()[0];
            assert_eq!(output, (x + c) % q);
        }
    }

    #[test]
    fn arithmetic_half_gate() {
        let mut rng = thread_rng();
        let q = rng.gen_prime();
        let c = circuits::TestMulGate(q);

        for _ in 0..16 {
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            let output = Dummy::eval(&c, &[x, y]).unwrap()[0];
            assert_eq!(output, x * y % q);
        }
    }
}

#[cfg(test)]
mod fancy_proj {
    use crate::{
        circuit::{CircuitExecutor, circuits},
        dummy::Dummy,
        util::RngExt,
    };
    use rand::thread_rng;

    #[test]
    fn mod_change() {
        let mut rng = thread_rng();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let c = circuits::TestModChange(p, q);

        for _ in 0..16 {
            let x = rng.gen_u16() % p;
            let output = Dummy::eval(&c, &[x]).unwrap()[0];
            assert_eq!(output, x % q);
        }
    }

    #[test]
    fn add_many_mod_change() {
        let mut rng = thread_rng();
        let n = 113;
        let c = circuits::TestAddManyModChange(n);

        for _ in 0..64 {
            let inputs =
                (0..<circuits::TestAddManyModChange as CircuitExecutor<Dummy>>::ninputs(&c))
                    .map(|i| {
                        rng.gen_u16()
                            % <circuits::TestAddManyModChange as CircuitExecutor<Dummy>>::modulus(
                                &c, i,
                            )
                    })
                    .collect::<Vec<_>>();
            let expected: u16 = inputs.iter().sum();
            let output = Dummy::eval(&c, &inputs).unwrap()[0];
            assert_eq!(output, expected);
        }
    }
}

#[cfg(test)]
mod bundle_gadgets {
    use crate::{
        circuit::circuits,
        dummy::Dummy,
        util::{RngExt, crt_factor, crt_inv_factor, factor, u128_from_bits, u128_to_bits},
    };
    use rand::thread_rng;

    #[test]
    fn test_bundle_input_output() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::TestBundleInputOutput(factor(q));

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = Dummy::eval(&c, &crt_factor(x, q)).unwrap();
            let output = crt_inv_factor(&y, q);
            assert_eq!(output, x);
        }
    }

    #[test]
    fn test_shift_extend() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let shift_size = rng.gen_usize() % nbits;
            let x = rng.gen_u128() % q;
            let c = circuits::TestShiftExtend(nbits, shift_size);

            let inputs = u128_to_bits(x, nbits);
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(u128_from_bits(&output), x << shift_size);
        }
    }
}

#[cfg(test)]
mod crt_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::Dummy,
        util::{self, RngExt, crt_factor, crt_inv_factor, factor},
    };

    #[test]
    fn test_addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::TestCrtAddition(factor(q));

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, (x + y) % q);
        }
    }

    #[test]
    fn test_subtraction() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::TestCrtSubtraction(util::factor(q));

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, (x + q - y) % q);
        }
    }

    #[test]
    fn test_cmul() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(16);
        let y = rng.gen_u128() % q;
        let c = circuits::TestCrtCmul(util::factor(q), y);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let z = Dummy::eval(&c, &crt_factor(x, q)).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, (x * y) % q);
        }
    }
}

#[cfg(test)]
mod arithmetic_bundle_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::Dummy,
        util::{RngExt, crt_factor, crt_inv_factor, factor},
    };

    #[test]
    fn test_multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::TestCrtMultiplication(factor(q));

        for _ in 0..16 {
            let x = rng.gen_u64() as u128 % q;
            let y = rng.gen_u64() as u128 % q;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, (x * y) % q);
        }
    }

    #[test]
    fn test_mask() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::TestMask(factor(q));

        for _ in 0..16 {
            let b = rng.gen_bool();
            let x = rng.gen_u128() % q;

            let mut inputs = vec![b as u16];
            inputs.extend(crt_factor(x, q));
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = crt_inv_factor(&z, q);
            if b {
                assert_eq!(output, x);
            } else {
                assert_eq!(output, 0);
            }
        }
    }
}

#[cfg(test)]
mod crt_proj_gadgets {
    use crate::{
        circuit::circuits,
        dummy::Dummy,
        util::{RngExt, crt_factor, crt_inv_factor, factor, modulus_with_width, product},
    };
    use rand::thread_rng;

    #[test]
    fn test_cexp() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let y = rng.gen_u16() % 10;
        let c = circuits::TestCrtCexp(factor(q), y);

        for _ in 0..64 {
            let x = rng.gen_u16() as u128 % q;
            let z = Dummy::eval(&c, &crt_factor(x, q)).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, x.pow(y as u32) % q);
        }
    }

    #[test]
    #[ignore]
    fn test_division() {
        let mut rng = thread_rng();

        for _ in 0..16 {
            let qs = rng.gen_usable_factors();
            let n = qs.len();
            let q = crate::util::product(&qs);
            let c = circuits::TestCrtDivision(factor(q));

            let q_ = crate::util::product(&qs[..n - 1]);
            let pt_x = rng.gen_u128() % q_;
            let pt_y = rng.gen_u128() % q_;

            let mut inputs = crt_factor(pt_x, q);
            inputs.extend(crt_factor(pt_y, q));
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, pt_x / pt_y);
        }
    }

    #[test]
    fn test_remainder() {
        let mut rng = thread_rng();
        let ps = rng.gen_usable_factors();
        let q = ps.iter().fold(1, |acc, &x| (x as u128) * acc);
        let p = ps[rng.gen_u16() as usize % ps.len()];
        let c = circuits::TestCrtRemainder(ps, p);

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let z = Dummy::eval(&c, &crt_factor(x, q)).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, x % p as u128);
        }
    }

    #[test]
    fn test_relu() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let c = circuits::TestRelu(factor(q));

        for _ in 0..128 {
            let input = rng.gen_u128() % q;
            let expected = if input < q / 2 { input } else { 0 };
            let z = Dummy::eval(&c, &crt_factor(input, q)).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn test_sgn() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let c = circuits::TestSgn(factor(q));

        for _ in 0..128 {
            let input = rng.gen_u128() % q;
            let expected = if input < q / 2 { 1 } else { q - 1 };
            let z = Dummy::eval(&c, &crt_factor(input, q)).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn test_leq() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let c = circuits::TestLeq(factor(q));

        // Let's have at least one test where they are surely equal.
        let x = rng.gen_u128() % q / 2;
        let mut inputs = crt_factor(x, q);
        inputs.extend(crt_factor(x, q));
        let output = Dummy::eval(&c, &inputs).unwrap()[0];
        assert_eq!(output, (x < x) as u16);

        for _ in 0..64 {
            let x = rng.gen_u128() % q / 2;
            let y = rng.gen_u128() % q / 2;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let output = Dummy::eval(&c, &inputs).unwrap()[0];
            assert_eq!(output, (x < y) as u16);
        }
    }

    #[test]
    fn test_max() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let n = 10;
        let c = circuits::TestMax(factor(q), n);

        for _ in 0..16 {
            let inputs = (0..n).map(|_| rng.gen_u128() % (q / 2)).collect::<Vec<_>>();
            let expected = *inputs.iter().max().unwrap();

            let inputs = inputs
                .into_iter()
                .flat_map(|x| crt_factor(x, q))
                .collect::<Vec<_>>();
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = crt_inv_factor(&z, q);
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn test_crt_to_pmr() {
        fn to_pmr_pt(x: u128, ps: &[u16]) -> Vec<u16> {
            let mut ds = vec![0; ps.len()];
            let mut q = 1;
            for i in 0..ps.len() {
                let p = ps[i] as u128;
                ds[i] = ((x / q) % p) as u16;
                q *= p;
            }
            ds
        }

        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            let ps = rng.gen_usable_factors();
            let q = product(&ps);

            let input = rng.gen_u128() % q;
            let expected = to_pmr_pt(input, &ps);
            let c = circuits::TestCrtToPmr(ps);
            let output = Dummy::eval(&c, &crt_factor(input, q)).unwrap();
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn test_pmr_lt() {
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            let qs = rng.gen_usable_factors();
            let n = qs.len();
            let q = product(&qs);
            let q_ = product(&qs[..n - 1]);
            let pt_x = rng.gen_u128() % q_;
            let pt_y = rng.gen_u128() % q_;
            let c = circuits::TestPmrLessThan(qs);
            let mut inputs = crt_factor(pt_x, q);
            inputs.extend(crt_factor(pt_y, q));
            let output = Dummy::eval(&c, &inputs).unwrap()[0];
            if pt_x < pt_y {
                assert_eq!(output, 1);
            } else {
                assert_eq!(output, 0);
            }
        }
    }

    #[test]
    fn test_pmr_geq() {
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            let qs = rng.gen_usable_factors();
            let n = qs.len();
            let q = product(&qs);
            let q_ = product(&qs[..n - 1]);
            let pt_x = rng.gen_u128() % q_;
            let pt_y = rng.gen_u128() % q_;
            let c = circuits::TestPmrGreaterThanOrEqual(qs);
            let mut inputs = crt_factor(pt_x, q);
            inputs.extend(crt_factor(pt_y, q));
            let output = Dummy::eval(&c, &inputs).unwrap()[0];
            if pt_x >= pt_y {
                assert_eq!(output, 1);
            } else {
                assert_eq!(output, 0);
            }
        }
    }
}

#[cfg(test)]
mod arithmetic_proj_bundle_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::Dummy,
        util::{RngExt, as_mixed_radix, crt_factor, factor, from_mixed_radix, product},
    };

    #[test]
    fn test_eq_bundles() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::TestEqBundles(factor(q));

        // Let's have at least one test where they are surely equal.
        let x = rng.gen_u128() % q;
        let mut inputs = crt_factor(x, q);
        inputs.extend(crt_factor(x, q));
        let output = Dummy::eval(&c, &inputs).unwrap()[0];
        assert_eq!(output, (x == x) as u16);

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let output = Dummy::eval(&c, &inputs).unwrap()[0];
            assert_eq!(output, (x == y) as u16);
        }
    }

    #[test]
    fn test_mixed_radix_addition() {
        let mut rng = thread_rng();
        let nargs = 2 + rng.gen_usize() % 100;
        let moduli = (0..7).map(|_| rng.gen_modulus()).collect::<Vec<_>>();
        let q: u128 = moduli.iter().map(|&q| q as u128).product();
        let circ = circuits::TestMixedRadixAddition(moduli.clone(), nargs);

        // Test maximum overflow.
        let mut inputs = Vec::new();
        for _ in 0..nargs {
            inputs.extend(as_mixed_radix(q - 1, &moduli).iter());
        }
        let output = Dummy::eval(&circ, &inputs).unwrap();
        assert_eq!(
            from_mixed_radix(&output, &moduli),
            (q - 1) * (nargs as u128) % q
        );

        // Test random values.
        for _ in 0..4 {
            let mut expected = 0;
            let mut inputs = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % q;
                expected = (expected + x) % q;
                inputs.extend(as_mixed_radix(x, &moduli).iter());
            }
            let output = Dummy::eval(&circ, &inputs).unwrap();
            assert_eq!(from_mixed_radix(&output, &moduli), expected);
        }
    }

    #[test]
    fn test_mixed_radix_addition_msb_only() {
        let mut rng = thread_rng();
        let nargs = 2 + rng.gen_usize() % 10;
        let moduli = (0..7).map(|_| rng.gen_modulus()).collect::<Vec<_>>();
        let q = product(&moduli);
        let circ = circuits::TestMixedRadixAdditionMSBOnly(moduli.clone(), nargs);

        // Test maximum overflow.
        let mut inputs = Vec::new();
        for _ in 0..nargs {
            inputs.extend(as_mixed_radix(q - 1, &moduli).iter());
        }
        let output = Dummy::eval(&circ, &inputs).unwrap()[0];
        assert_eq!(
            output,
            *as_mixed_radix((q - 1) * (nargs as u128) % q, &moduli)
                .last()
                .unwrap()
        );

        // Test random values.
        for _ in 0..4 {
            let mut expected = 0;
            let mut inputs = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % q;
                expected = (expected + x) % q;
                inputs.extend(as_mixed_radix(x, &moduli).iter());
            }
            let output = Dummy::eval(&circ, &inputs).unwrap()[0];
            assert_eq!(output, *as_mixed_radix(expected, &moduli).last().unwrap());
        }
    }
}

#[cfg(test)]
mod binary_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::Dummy,
        util::{self, RngExt},
    };

    #[test]
    fn test_binary_addition() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << 64;
        let c = circuits::TestBinaryAddition(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = util::u128_to_bits(x, nbits);
            inputs.extend(util::u128_to_bits(y, nbits));
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(util::u128_from_bits(&output[1..]), (x + y) % q);
            assert_eq!(output[0], (x + y >= q) as u16);
        }
    }

    #[test]
    fn test_binary_subtraction() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::TestBinarySubtraction(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = util::u128_to_bits(x, nbits);
            inputs.extend(util::u128_to_bits(y, nbits));
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(
                util::u128_from_bits(&output[1..]),
                x.overflowing_sub(y).0 % q
            );
            assert_eq!(output[0], (y != 0 && x >= y) as u16);
        }
    }

    #[test]
    fn test_binary_lt() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::TestBinaryLessThan(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = util::u128_to_bits(x, nbits);
            inputs.extend(util::u128_to_bits(y, nbits));
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(util::u128_from_bits(&output) > 0, x < y);
        }
    }

    #[test]
    fn test_binary_lt_signed() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        let c = circuits::TestBinaryLessThanSigned(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = util::u128_to_bits(x, nbits);
            inputs.extend(util::u128_to_bits(y, nbits));
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(output.len(), 1);
            assert_eq!(output[0] > 0, (x as i16) < (y as i16));
        }
    }

    #[test]
    fn test_binary_multiplication_lower_half() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::TestBinaryMultiplicationLowerHalf(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = util::u128_to_bits(x, nbits);
            inputs.extend(util::u128_to_bits(y, nbits));
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(util::u128_from_bits(&output), (x * y) % q);
        }
    }

    #[test]
    fn test_binary_multiplication() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << 64;
        let c = circuits::TestBinaryMultiplication(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = util::u128_to_bits(x, nbits);
            inputs.extend(util::u128_to_bits(y, nbits));
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(util::u128_from_bits(&output), x * y);
        }
    }

    #[test]
    fn test_binary_division() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::TestBinaryDivision(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let mut y = rng.gen_u128() % q;
            while y == 0 {
                y = rng.gen_u128() % q;
            }
            let mut inputs = util::u128_to_bits(x, nbits);
            inputs.extend(util::u128_to_bits(y, nbits));
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(util::u128_from_bits(&output), x / y);
        }
    }

    #[test]
    fn test_bin_abs() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::TestBinaryAbs(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let output = Dummy::eval(&c, &util::u128_to_bits(x, nbits)).unwrap();
            assert_eq!(
                util::u128_from_bits(&output),
                if x >> (nbits - 1) > 0 {
                    ((!x) + 1) & ((1 << nbits) - 1)
                } else {
                    x
                }
            );
        }
    }

    #[test]
    fn test_binary_eq() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::TestBinaryEqBundles(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = util::u128_to_bits(x, nbits);
            inputs.extend(util::u128_to_bits(y, nbits));
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(output[0], (x == y) as u16);
        }
    }

    #[test]
    fn test_binary_rsa() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let shift_size = rng.gen_usize() % nbits;
            let c = circuits::TestBinaryArithmeticRightShift(nbits, shift_size);
            let output = Dummy::eval(&c, &util::u128_to_bits(x, nbits)).unwrap();
            assert_eq!(
                util::u128_from_bits(&output) as i64,
                (x as i64) >> shift_size
            );
        }
    }

    #[test]
    fn test_binary_rsl() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let shift_size = rng.gen_usize() % nbits;
            let c = circuits::TestBinaryLogicalRightShift(nbits, shift_size);
            let output = Dummy::eval(&c, &util::u128_to_bits(x, nbits)).unwrap();
            assert_eq!(util::u128_from_bits(&output), x >> shift_size);
        }
    }

    #[test]
    fn test_bin_demux() {
        let mut rng = thread_rng();
        let nbits = 8;
        let q = 1 << nbits;
        let c = circuits::TestBinaryDemux(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let output = Dummy::eval(&c, &util::u128_to_bits(x, nbits)).unwrap();
            for (i, y) in output.into_iter().enumerate() {
                if i as u128 == x {
                    assert_eq!(y, 1);
                } else {
                    assert_eq!(y, 0);
                }
            }
        }
    }

    #[test]
    fn test_bin_twos_complement() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::TestBinaryTwosComplement(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let output = Dummy::eval(&c, &util::u128_to_bits(x, nbits)).unwrap();
            assert_eq!(util::u128_from_bits(&output), (((!x) % q) + 1) % q);
        }
    }

    #[test]
    fn test_binary_max() {
        let mut rng = thread_rng();
        let n = 10;
        let nbits = 16;
        let q = 1 << nbits;
        let c = circuits::TestBinaryMax(nbits, n);

        for _ in 0..16 {
            let inputs = (0..n).map(|_| rng.gen_u128() % q).collect::<Vec<_>>();
            let expected = *inputs.iter().max().unwrap();

            let inputs = inputs
                .into_iter()
                .flat_map(|x| util::u128_to_bits(x, nbits))
                .collect::<Vec<_>>();
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = util::u128_from_bits(&z);
            assert_eq!(output, expected);
        }
    }
}

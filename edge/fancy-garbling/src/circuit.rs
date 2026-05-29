//! DSL for creating circuits compatible with fancy-garbling in the old-fashioned way,
//! where you create a circuit for a computation then garble it.

use crate::{BinaryBundle, Bundle, CrtBundle, HasModulus, fancy::Fancy};
use itertools::Itertools;
use swanky_channel::Channel;
use swanky_error::Result;

mod binary;
pub use binary::{BinaryCircuit, BinaryGate};

/// Trait for flattening the output of a [`CircuitExecutor`] into a vector of
/// wires.
pub trait Flatten {
    /// The type of the elements in the output vector.
    type Item;

    /// Flatten a set of wires into a single vector of wires.
    fn flatten(self) -> Vec<Self::Item>;
}

impl<T: Clone + HasModulus> Flatten for Vec<T> {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        self
    }
}

impl<T: Clone + HasModulus> Flatten for T {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        vec![self]
    }
}

impl<T: Clone + HasModulus> Flatten for (T, T) {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        vec![self.0]
    }
}

impl<T: Clone + HasModulus> Flatten for Bundle<T> {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        self.wires().to_vec()
    }
}

impl<T: Clone + HasModulus> Flatten for BinaryBundle<T> {
    type Item = T;

    fn flatten(self) -> Vec<T> {
        self.extract().wires().to_vec()
    }
}

impl<T: Clone + HasModulus> Flatten for CrtBundle<T> {
    type Item = T;

    fn flatten(self) -> Vec<T> {
        self.extract().wires().to_vec()
    }
}

impl<T: Clone + HasModulus> Flatten for Vec<CrtBundle<T>> {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        self.into_iter().map(|bundle| bundle.flatten()).concat()
    }
}

impl<T: Clone + HasModulus> Flatten for (T, BinaryBundle<T>) {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        [vec![self.0], self.1.flatten()].concat()
    }
}

impl<T: Clone + HasModulus> Flatten for (BinaryBundle<T>, T) {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        [self.0.flatten(), vec![self.1]].concat()
    }
}

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
///     type Input = (F::Item, F::Item);
///     type Output = F::Item;
///
///     fn execute(
///         &self,
///         backend: &mut F,
///         inputs: &Self::Input,
///         channel: &mut Channel,
///     ) -> Result<Self::Output> {
///         Ok(backend.add(&inputs.0, &inputs.1))
///     }
///
///     fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
///         assert_eq!(inputs.len(), 2);
///         (inputs[0].clone(), inputs[1].clone())
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
pub trait CircuitExecutor<F: Fancy>: Circuit<F> {
    /// Map a vector of inputs to [`Circuit::Input`].
    ///
    /// # Panics
    /// This panics of the number of inputs does not match the expected input size.
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input;
    /// The number of inputs to provide to [`Circuit::execute`].
    fn ninputs(&self) -> usize;
    /// The modulus for input `i`.
    fn modulus(&self, i: usize) -> u16;
}

/// Trait for defining arbitrary [`Fancy`] circuits.
pub trait Circuit<F: Fancy> {
    /// The input type of the circuit.
    type Input;
    /// The output type of the circuit.
    type Output: Flatten<Item = F::Item>;

    /// Execute a circuit on a given [`Fancy`] backend using the provided inputs.
    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output>;
}

pub mod circuits {
    //! A collection of test circuits.

    pub mod fancy {
        //! Circuits that test [`Fancy`].

        use crate::{
            Fancy,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`Fancy::constant`] on binary values.
        pub struct TestBinaryConstant;
        impl<F: Fancy> Circuit<F> for TestBinaryConstant {
            type Input = ();
            type Output = Vec<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                _: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let outputs = vec![
                    backend.constant(0, 2, channel)?,
                    backend.constant(1, 2, channel)?,
                ];
                Ok(outputs)
            }
        }
        impl<F: Fancy> CircuitExecutor<F> for TestBinaryConstant {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert!(inputs.is_empty());
            }

            fn ninputs(&self) -> usize {
                0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }
    }

    pub mod binary {
        //! Circuits that test [`FancyBinary`].

        use crate::{
            BinaryBundle, FancyBinary,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`FancyBinary::negate`].
        pub struct TestNegateGate;
        impl<F: FancyBinary> Circuit<F> for TestNegateGate {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.negate(input))
            }
        }
        impl<F: FancyBinary> CircuitExecutor<F> for TestNegateGate {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`FancyBinary::and`].
        pub struct TestAndGate;
        impl<F: FancyBinary> Circuit<F> for TestAndGate {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.and(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: FancyBinary> CircuitExecutor<F> for TestAndGate {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
            }

            fn ninputs(&self) -> usize {
                2
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`FancyBinary::and_many`].
        pub struct TestAndGateFanN(pub usize);
        impl<F: FancyBinary> Circuit<F> for TestAndGateFanN {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.and_many(inputs, channel)
            }
        }

        impl<F: FancyBinary> CircuitExecutor<F> for TestAndGateFanN {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
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
        impl<F: FancyBinary> Circuit<F> for TestOrGateFanN {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.or_many(inputs, channel)
            }
        }
        impl<F: FancyBinary> CircuitExecutor<F> for TestOrGateFanN {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
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
        impl<F: FancyBinary> Circuit<F> for TestXorGateFanN {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.xor_many(inputs))
            }
        }
        impl<F: FancyBinary> CircuitExecutor<F> for TestXorGateFanN {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
            }

            fn ninputs(&self) -> usize {
                self.0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`FancyBinary::negate`] over a [`BinaryBundle`].
        pub struct TestBinaryNegate(pub usize);
        impl<F: FancyBinary> Circuit<F> for TestBinaryNegate {
            type Input = Vec<F::Item>;
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(BinaryBundle::new(
                    inputs.iter().map(|x| backend.negate(x)).collect::<Vec<_>>(),
                ))
            }
        }
        impl<F: FancyBinary> CircuitExecutor<F> for TestBinaryNegate {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
            }

            fn ninputs(&self) -> usize {
                self.0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }
    }

    pub mod arithmetic {
        //! Circuits that test [`FancyArithmetic`].

        use crate::{
            FancyArithmetic,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`FancyArithmetic::add`].
        pub struct TestAddition(pub u16);
        impl<F: FancyArithmetic> Circuit<F> for TestAddition {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.add(&inputs.0, &inputs.1))
            }
        }
        impl<F: FancyArithmetic> CircuitExecutor<F> for TestAddition {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
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
        impl<F: FancyArithmetic> Circuit<F> for TestAddMany {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.add_many(inputs))
            }
        }
        impl<F: FancyArithmetic> CircuitExecutor<F> for TestAddMany {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.1);
                inputs
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
        impl<F: FancyArithmetic> Circuit<F> for TestSubtraction {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.sub(&inputs.0, &inputs.1))
            }
        }
        impl<F: FancyArithmetic> CircuitExecutor<F> for TestSubtraction {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
            }

            fn ninputs(&self) -> usize {
                2
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing [`FancyArithmetic::mul`].
        pub struct TestMulGate(pub u16);
        impl<F: FancyArithmetic> Circuit<F> for TestMulGate {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mul(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: FancyArithmetic> CircuitExecutor<F> for TestMulGate {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
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
        impl<F: FancyArithmetic> Circuit<F> for TestMulGateUnequalMods {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mul(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: FancyArithmetic> CircuitExecutor<F> for TestMulGateUnequalMods {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
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
        impl<F: FancyArithmetic> Circuit<F> for TestCmul {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.cmul(input, self.1))
            }
        }
        impl<F: FancyArithmetic> CircuitExecutor<F> for TestCmul {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing constant gates.
        pub struct TestConstants(pub u16, pub u16);
        impl<F: FancyArithmetic> Circuit<F> for TestConstants {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let constant = backend.constant(self.1, self.0, channel)?;
                Ok(backend.add(input, &constant))
            }
        }
        impl<F: FancyArithmetic> CircuitExecutor<F> for TestConstants {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }
    }

    pub mod proj {
        //! Circuits that test [`FancyProj`].

        use crate::{
            FancyArithmetic, FancyProj,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`FancyProj::proj`].
        pub struct TestProj(pub u16);
        impl<F: FancyProj> Circuit<F> for TestProj {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let tab = (0..self.0).map(|i| (i + 1) % self.0).collect();
                backend.proj(input, self.0, Some(tab), channel)
            }
        }
        impl<F: FancyProj> CircuitExecutor<F> for TestProj {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
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
        impl<F: FancyProj> Circuit<F> for TestProjRand {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.proj(input, self.0, Some(self.1.clone()), channel)
            }
        }
        impl<F: FancyProj> CircuitExecutor<F> for TestProjRand {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
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
        impl<F: FancyProj> Circuit<F> for TestModChange {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let y = backend.mod_change(input, self.1, channel)?;
                backend.mod_change(&y, self.0, channel)
            }
        }
        impl<F: FancyProj> CircuitExecutor<F> for TestModChange {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
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
        impl<F: FancyProj + FancyArithmetic> Circuit<F> for TestAddManyModChange {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let wires = inputs
                    .iter()
                    .map(|x| backend.mod_change(x, self.0 as u16 + 1, channel))
                    .collect::<Result<Vec<_>>>()?;
                Ok(backend.add_many(&wires))
            }
        }
        impl<F: FancyProj + FancyArithmetic> CircuitExecutor<F> for TestAddManyModChange {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
            }

            fn ninputs(&self) -> usize {
                self.0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }
    }

    pub mod bundle_gadgets {
        //! Circuits that test [`BundleGadgets`].

        use crate::{
            BinaryBundle, Bundle, BundleGadgets, CrtBundle,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`CrtBundle`]s.
        pub struct TestBundleInputOutput(pub Vec<u16>);
        impl<F: BundleGadgets> Circuit<F> for TestBundleInputOutput {
            type Input = CrtBundle<F::Item>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                _: &mut F,
                input: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(input.clone())
            }
        }
        impl<F: BundleGadgets> CircuitExecutor<F> for TestBundleInputOutput {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
            }

            fn ninputs(&self) -> usize {
                self.0.len()
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i]
            }
        }

        /// Circuit for testing [`BundleGadgets::shift_extend`].
        pub struct TestShiftExtend(pub usize, pub usize);
        impl<F: BundleGadgets> Circuit<F> for TestShiftExtend {
            type Input = BinaryBundle<F::Item>;
            type Output = Bundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.shift_extend(input, self.1, channel)
            }
        }
        impl<F: BundleGadgets> CircuitExecutor<F> for TestShiftExtend {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                BinaryBundle::new(inputs)
            }

            fn ninputs(&self) -> usize {
                self.0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }
    }

    pub mod crt_gadgets {
        //! Circuits that test [`CrtGadgets`].

        use crate::{
            CrtBundle, CrtGadgets,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`CrtGadgets::crt_add`].
        pub struct TestCrtAddition(pub Vec<u16>);
        impl<F: CrtGadgets> Circuit<F> for TestCrtAddition {
            type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.crt_add(&inputs.0, &inputs.1))
            }
        }
        impl<F: CrtGadgets> CircuitExecutor<F> for TestCrtAddition {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * 2);
                let length = self.0.len();
                let (x, y) = inputs.split_at(length);
                let x = CrtBundle::new(x.to_vec());
                let y = CrtBundle::new(y.to_vec());
                (x, y)
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
        impl<F: CrtGadgets> Circuit<F> for TestCrtSubtraction {
            type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.crt_sub(&inputs.0, &inputs.1))
            }
        }
        impl<F: CrtGadgets> CircuitExecutor<F> for TestCrtSubtraction {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * 2);
                let length = self.0.len();
                let (x, y) = inputs.split_at(length);
                let x = CrtBundle::new(x.to_vec());
                let y = CrtBundle::new(y.to_vec());
                (x, y)
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
        impl<F: CrtGadgets> Circuit<F> for TestCrtCmul {
            type Input = CrtBundle<F::Item>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.crt_cmul(input, self.1))
            }
        }
        impl<F: CrtGadgets> CircuitExecutor<F> for TestCrtCmul {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
            }

            fn ninputs(&self) -> usize {
                self.0.len()
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i]
            }
        }
    }

    pub mod arithmetic_bundle_gadgets {
        //! Circuits that test [`ArithmeticBundleGadgets`].

        use crate::{
            ArithmeticBundleGadgets, Bundle, CrtBundle,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`ArithmeticBundleGadgets::mul_bundles`].
        pub struct TestCrtMultiplication(pub Vec<u16>);
        impl<F: ArithmeticBundleGadgets> Circuit<F> for TestCrtMultiplication {
            type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
            type Output = Bundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mul_bundles(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: ArithmeticBundleGadgets> CircuitExecutor<F> for TestCrtMultiplication {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * 2);
                let length = self.0.len();
                let (x, y) = inputs.split_at(length);
                let x = CrtBundle::new(x.to_vec());
                let y = CrtBundle::new(y.to_vec());
                (x, y)
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
        impl<F: ArithmeticBundleGadgets> Circuit<F> for TestMask {
            type Input = (F::Item, Bundle<F::Item>);
            type Output = Bundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mask(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: ArithmeticBundleGadgets> CircuitExecutor<F> for TestMask {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() + 1);
                (inputs[0].clone(), Bundle::new(inputs[1..].to_vec()))
            }

            fn ninputs(&self) -> usize {
                self.0.len() + 1
            }

            fn modulus(&self, i: usize) -> u16 {
                if i == 0 { 2 } else { self.0[i - 1] }
            }
        }
    }

    pub mod crt_proj_gadgets {
        //! Circuits for testing [`CrtProjGadgets`].

        use crate::{
            Bundle, CrtBundle, CrtProjGadgets,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`CrtProjGadgets::crt_cexp`].
        pub struct TestCrtCexp(pub Vec<u16>, pub u16);
        impl<F: CrtProjGadgets> Circuit<F> for TestCrtCexp {
            type Input = CrtBundle<F::Item>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_cexp(input, self.1, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestCrtCexp {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
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
        impl<F: CrtProjGadgets> Circuit<F> for TestCrtDivision {
            type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_div(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestCrtDivision {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * 2);
                let length = self.0.len();
                let (x, y) = inputs.split_at(length);
                let x = CrtBundle::new(x.to_vec());
                let y = CrtBundle::new(y.to_vec());
                (x, y)
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
        impl<F: CrtProjGadgets> Circuit<F> for TestCrtRemainder {
            type Input = CrtBundle<F::Item>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_rem(input, self.1, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestCrtRemainder {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
            }

            fn ninputs(&self) -> usize {
                self.0.len()
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i]
            }
        }

        /// Circuit for testing multiple CRT operations.
        pub struct TestComplexGadget(pub Vec<u16>, pub usize);
        impl<F: CrtProjGadgets> Circuit<F> for TestComplexGadget {
            type Input = Vec<CrtBundle<F::Item>>;
            type Output = Vec<CrtBundle<F::Item>>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let mut outputs = Vec::with_capacity(inputs.len());
                for x in inputs.iter() {
                    let c = backend.crt_constant_bundle(1, x.composite_modulus(), channel)?;
                    let y = backend.crt_mul(x, &c, channel)?;
                    let z = backend.crt_relu(&y, "100%", None, channel)?;
                    outputs.push(z);
                }
                Ok(outputs)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestComplexGadget {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * self.1);
                inputs
                    .chunks_exact(self.0.len())
                    .map(|x| CrtBundle::new(x.to_vec()))
                    .collect()
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
        impl<F: CrtProjGadgets> Circuit<F> for TestRelu {
            type Input = CrtBundle<F::Item>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_relu(input, "100%", None, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestRelu {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
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
        impl<F: CrtProjGadgets> Circuit<F> for TestSgn {
            type Input = CrtBundle<F::Item>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_sgn(input, "100%", None, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestSgn {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
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
        impl<F: CrtProjGadgets> Circuit<F> for TestLeq {
            type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_lt(&inputs.0, &inputs.1, "100%", channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestLeq {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * 2);
                let (x, y) = inputs.split_at(self.0.len());
                let x = CrtBundle::new(x.to_vec());
                let y = CrtBundle::new(y.to_vec());
                (x, y)
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
        impl<F: CrtProjGadgets> Circuit<F> for TestMax {
            type Input = Vec<CrtBundle<F::Item>>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_max(inputs, "100%", channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestMax {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * self.1);
                inputs
                    .chunks_exact(self.0.len())
                    .map(|x| CrtBundle::new(x.to_vec()))
                    .collect()
            }

            fn ninputs(&self) -> usize {
                self.0.len() * self.1
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i % self.0.len()]
            }
        }

        /// Circuit for testing [`CrtProjGadgets::crt_to_pmr`].
        pub struct TestCrtToPmr(pub Vec<u16>);
        impl<F: CrtProjGadgets> Circuit<F> for TestCrtToPmr {
            type Input = CrtBundle<F::Item>;
            type Output = Bundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_to_pmr(input, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestCrtToPmr {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
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
        impl<F: CrtProjGadgets> Circuit<F> for TestPmrLessThan {
            type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.pmr_lt(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestPmrLessThan {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * 2);
                let (x, y) = inputs.split_at(self.0.len());
                let x = CrtBundle::new(x.to_vec());
                let y = CrtBundle::new(y.to_vec());
                (x, y)
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
        impl<F: CrtProjGadgets> Circuit<F> for TestPmrGreaterThanOrEqual {
            type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.pmr_geq(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitExecutor<F> for TestPmrGreaterThanOrEqual {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * 2);
                let (x, y) = inputs.split_at(self.0.len());
                let x = CrtBundle::new(x.to_vec());
                let y = CrtBundle::new(y.to_vec());
                (x, y)
            }

            fn ninputs(&self) -> usize {
                self.0.len() * 2
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i % self.0.len()]
            }
        }
    }

    pub mod arithmetic_proj_bundle_gadgets {
        //! Circuits for testing [`ArithmeticProjBundleGadgets`].

        use crate::{
            ArithmeticProjBundleGadgets, Bundle, CrtBundle,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`ArithmeticProjBundleGadgets::eq_bundles`].
        pub struct TestEqBundles(pub Vec<u16>);
        impl<F: ArithmeticProjBundleGadgets> Circuit<F> for TestEqBundles {
            type Input = (CrtBundle<F::Item>, CrtBundle<F::Item>);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.eq_bundles(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: ArithmeticProjBundleGadgets> CircuitExecutor<F> for TestEqBundles {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * 2);
                let (x, y) = inputs.split_at(self.0.len());
                let x = CrtBundle::new(x.to_vec());
                let y = CrtBundle::new(y.to_vec());
                (x, y)
            }

            fn ninputs(&self) -> usize {
                self.0.len() * 2
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i % self.0.len()]
            }
        }

        /// Circuit for testing [`ArithmeticProjBundleGadgets::mixed_radix_addition`].
        pub struct TestMixedRadixAddition(pub Vec<u16>, pub usize);
        impl<F: ArithmeticProjBundleGadgets> Circuit<F> for TestMixedRadixAddition {
            type Input = Vec<Bundle<F::Item>>;
            type Output = Bundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mixed_radix_addition(inputs, channel)
            }
        }
        impl<F: ArithmeticProjBundleGadgets> CircuitExecutor<F> for TestMixedRadixAddition {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                inputs
                    .chunks_exact(self.0.len())
                    .map(|v| Bundle::new(v.to_vec()))
                    .collect()
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
        impl<F: ArithmeticProjBundleGadgets> Circuit<F> for TestMixedRadixAdditionMSBOnly {
            type Input = Vec<Bundle<F::Item>>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mixed_radix_addition_msb_only(inputs, channel)
            }
        }
        impl<F: ArithmeticProjBundleGadgets> CircuitExecutor<F> for TestMixedRadixAdditionMSBOnly {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                inputs
                    .chunks_exact(self.0.len())
                    .map(|v| Bundle::new(v.to_vec()))
                    .collect()
            }

            fn ninputs(&self) -> usize {
                self.0.len() * self.1
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i % self.0.len()]
            }
        }
    }

    pub mod binary_gadgets {
        //! Circuits that test [`BinaryGadgets`].

        use crate::{
            BinaryBundle, BinaryGadgets,
            circuit::{Circuit, CircuitExecutor},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`BinaryGadgets::bin_constant_bundle`].
        pub struct TestConstantBundle(pub u128, pub usize);
        impl<F: BinaryGadgets> Circuit<F> for TestConstantBundle {
            type Input = ();
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                _: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_constant_bundle(self.0, self.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestConstantBundle {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert!(inputs.is_empty());
            }

            fn ninputs(&self) -> usize {
                0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`BinaryGadgets::bin_and`].
        pub struct TestBinaryAnd(pub usize);
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryAnd {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_and(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryAnd {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
            }

            fn ninputs(&self) -> usize {
                self.0 * 2
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`BinaryGadgets::bin_addition_no_carry`].
        pub struct TestBinaryAdditionNoCarry(pub usize);
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryAdditionNoCarry {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_addition_no_carry(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryAdditionNoCarry {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinarySubtraction {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = (F::Item, BinaryBundle<F::Item>);

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let (z, underflow) = backend.bin_subtraction(&inputs.0, &inputs.1, channel)?;
                Ok((underflow, z))
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinarySubtraction {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryMultiplication {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_mul(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryMultiplication {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryMultiplicationLowerHalf {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_multiplication_lower_half(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryMultiplicationLowerHalf {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryDivision {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_div(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryDivision {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryLessThan {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_lt(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryLessThan {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryLessThanSigned {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_lt_signed(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryLessThanSigned {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryArithmeticRightShift {
            type Input = BinaryBundle<F::Item>;
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.bin_rsa(input, self.1))
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryArithmeticRightShift {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                BinaryBundle::new(inputs)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryLogicalRightShift {
            type Input = BinaryBundle<F::Item>;
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_rsl(input, self.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryLogicalRightShift {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                BinaryBundle::new(inputs)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryEqBundles {
            type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_eq_bundles(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryEqBundles {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0 * 2);
                let (x, y) = inputs.split_at(self.0);
                let x = BinaryBundle::new(x.to_vec());
                let y = BinaryBundle::new(y.to_vec());
                (x, y)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryAbs {
            type Input = BinaryBundle<F::Item>;
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_abs(input, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryAbs {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                BinaryBundle::new(inputs)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryTwosComplement {
            type Input = BinaryBundle<F::Item>;
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_twos_complement(input, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryTwosComplement {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                BinaryBundle::new(inputs)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryDemux {
            type Input = BinaryBundle<F::Item>;
            type Output = Vec<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_demux(input, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryDemux {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                BinaryBundle::new(inputs)
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
        impl<F: BinaryGadgets> Circuit<F> for TestBinaryMax {
            type Input = Vec<BinaryBundle<F::Item>>;
            type Output = BinaryBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.bin_max(inputs, channel)
            }
        }
        impl<F: BinaryGadgets> CircuitExecutor<F> for TestBinaryMax {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                inputs
                    .chunks_exact(self.0)
                    .map(|v| BinaryBundle::new(v.to_vec()))
                    .collect()
            }

            fn ninputs(&self) -> usize {
                self.0 * self.1
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }
    }
}

#[cfg(test)]
mod fancy_binary {
    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::thread_rng;

    #[test]
    fn binary_constant_gates() {
        let c = circuits::fancy::TestBinaryConstant;
        let expected_0 = DummyVal::new(0, 2);
        let output_0 = Dummy::eval(&c, &()).unwrap()[0];
        assert_eq!(output_0, expected_0);
        let expected_1 = DummyVal::new(1, 2);
        let output_1 = Dummy::eval(&c, &()).unwrap()[1];
        assert_eq!(output_1, expected_1);
    }

    #[test]
    fn or_gate_fan_n() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 200);
        let c = circuits::binary::TestOrGateFanN(n);

        for _ in 0..16 {
            let inputs = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let expected = inputs.iter().fold(0, |acc, &x| x.val() | acc);
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(output.val(), expected);
        }
    }

    #[test]
    fn xor_gate_fan_n() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 200);
        let c = circuits::binary::TestXorGateFanN(n);

        for _ in 0..16 {
            let inputs = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let expected = inputs.iter().fold(0, |acc, &x| x.val() ^ acc);
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(output.val(), expected);
        }
    }

    #[test]
    fn binary_half_gate() {
        let mut rng = thread_rng();
        let c = circuits::binary::TestAndGate;

        for _ in 0..16 {
            let x = DummyVal::rand_bool(&mut rng);
            let y = DummyVal::rand_bool(&mut rng);
            let output = Dummy::eval(&c, &(x, y)).unwrap();
            assert_eq!(output.val(), x.val() * y.val() % 2);
        }
    }
}

#[cfg(test)]
mod fancy_arithmetic {
    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::thread_rng;

    #[test]
    fn constants() {
        let mut rng = thread_rng();
        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;
        let circ = circuits::arithmetic::TestConstants(q, c);

        for _ in 0..64 {
            let x = DummyVal::rand(q, &mut rng);
            let output = Dummy::eval(&circ, &x).unwrap();
            assert_eq!(output.val(), (x.val() + c) % q);
        }
    }

    #[test]
    fn arithmetic_half_gate() {
        let mut rng = thread_rng();
        let q = rng.gen_prime();
        let c = circuits::arithmetic::TestMulGate(q);

        for _ in 0..16 {
            let x = DummyVal::rand(q, &mut rng);
            let y = DummyVal::rand(q, &mut rng);
            let output = Dummy::eval(&c, &(x, y)).unwrap();
            assert_eq!(output.val(), (x.val() * y.val()) % q);
        }
    }
}

#[cfg(test)]
mod fancy_proj {
    use crate::{
        circuit::{CircuitExecutor, circuits},
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::thread_rng;

    #[test]
    fn mod_change() {
        let mut rng = thread_rng();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let c = circuits::proj::TestModChange(p, q);

        for _ in 0..16 {
            let x = DummyVal::rand(p, &mut rng);
            let output = Dummy::eval(&c, &x).unwrap();
            assert_eq!(output.val(), x.val() % q);
        }
    }

    #[test]
    fn add_many_mod_change() {
        let mut rng = thread_rng();
        let n = 113;
        let c = circuits::proj::TestAddManyModChange(n);

        for _ in 0..64 {
            let inputs = (0
                ..<circuits::proj::TestAddManyModChange as CircuitExecutor<Dummy>>::ninputs(&c))
                .map(|i| {
                    DummyVal::rand(
                        <circuits::proj::TestAddManyModChange as CircuitExecutor<Dummy>>::modulus(
                            &c, i,
                        ),
                        &mut rng,
                    )
                })
                .collect::<Vec<_>>();
            let expected: u16 = inputs.iter().map(|x| x.val()).sum();
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(output.val(), expected);
        }
    }
}

#[cfg(test)]
mod bundle_gadgets {
    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::{RngExt, factor},
    };
    use rand::{Rng, thread_rng};

    #[test]
    fn test_bundle_input_output() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::bundle_gadgets::TestBundleInputOutput(factor(q));

        for _ in 0..16 {
            let x = rng.r#gen::<u128>() % q;
            let input = DummyVal::to_crt(x, q);
            let y = Dummy::eval(&c, &input).unwrap();
            let output = DummyVal::from_crt(&y, q);
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
            let c = circuits::bundle_gadgets::TestShiftExtend(nbits, shift_size);

            let x = rng.gen_u128() % q;
            let input = DummyVal::to_binary(x, nbits);
            let output = Dummy::eval(&c, &input).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x << shift_size);
        }
    }
}

#[cfg(test)]
mod crt_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::{self, RngExt, factor},
    };

    #[test]
    fn test_crt_addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::crt_gadgets::TestCrtAddition(factor(q));

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let z = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, (x + y) % q);
        }
    }

    #[test]
    fn test_crt_subtraction() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::crt_gadgets::TestCrtSubtraction(util::factor(q));

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let z = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, (x + q - y) % q);
        }
    }

    #[test]
    fn test_cmul() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(16);
        let y = rng.gen_u128() % q;
        let c = circuits::crt_gadgets::TestCrtCmul(util::factor(q), y);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &x_input).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, (x * y) % q);
        }
    }
}

#[cfg(test)]
mod arithmetic_bundle_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::{RngExt, factor},
    };

    #[test]
    fn test_crt_multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::arithmetic_bundle_gadgets::TestCrtMultiplication(factor(q));

        for _ in 0..16 {
            let x = rng.gen_u64() as u128 % q;
            let y = rng.gen_u64() as u128 % q;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let z = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, (x * y) % q);
        }
    }

    #[test]
    fn test_mask() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::arithmetic_bundle_gadgets::TestMask(factor(q));

        for _ in 0..16 {
            let b = rng.gen_bool();
            let x = rng.gen_u128() % q;

            let b_input = DummyVal::new(b as u16, 2);
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &(b_input, x_input.extract())).unwrap();
            let output = DummyVal::from_crt(&z, q);
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
        dummy::{Dummy, DummyVal},
        util::{RngExt, factor, modulus_with_width, product},
    };
    use rand::thread_rng;

    #[test]
    fn test_cexp() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let y = rng.gen_u16() % 10;
        let c = circuits::crt_proj_gadgets::TestCrtCexp(factor(q), y);

        for _ in 0..64 {
            let x = rng.gen_u16() as u128 % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &x_input).unwrap();
            let output = DummyVal::from_crt(&z, q);
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
            let c = circuits::crt_proj_gadgets::TestCrtDivision(factor(q));

            let q_ = crate::util::product(&qs[..n - 1]);
            let pt_x = rng.gen_u128() % q_;
            let pt_y = rng.gen_u128() % q_;

            let pt_x_input = DummyVal::to_crt(pt_x, q_);
            let pt_y_input = DummyVal::to_crt(pt_y, q_);
            let z = Dummy::eval(&c, &(pt_x_input, pt_y_input)).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, pt_x / pt_y);
        }
    }

    #[test]
    fn test_remainder() {
        let mut rng = thread_rng();
        let ps = rng.gen_usable_factors();
        let q = ps.iter().fold(1, |acc, &x| (x as u128) * acc);
        let p = ps[rng.gen_u16() as usize % ps.len()];
        let c = circuits::crt_proj_gadgets::TestCrtRemainder(ps, p);

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &x_input).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, x % p as u128);
        }
    }

    #[test]
    fn test_relu() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let c = circuits::crt_proj_gadgets::TestRelu(factor(q));

        for _ in 0..128 {
            let x = rng.gen_u128() % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &x_input).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, if x < q / 2 { x } else { 0 });
        }
    }

    #[test]
    fn test_sgn() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let c = circuits::crt_proj_gadgets::TestSgn(factor(q));

        for _ in 0..128 {
            let x = rng.gen_u128() % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &x_input).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, if x < q / 2 { 1 } else { q - 1 });
        }
    }

    #[test]
    fn test_leq() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let c = circuits::crt_proj_gadgets::TestLeq(factor(q));

        // Let's have at least one test where they are surely equal.
        let x = rng.gen_u128() % q / 2;
        let x_input = DummyVal::to_crt(x, q);
        let output = Dummy::eval(&c, &(x_input.clone(), x_input)).unwrap();
        assert_eq!(output.val(), (x < x) as u16);

        for _ in 0..64 {
            let x = rng.gen_u128() % q / 2;
            let y = rng.gen_u128() % q / 2;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(output.val(), (x < y) as u16);
        }
    }

    #[test]
    fn test_max() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let n = 10;
        let c = circuits::crt_proj_gadgets::TestMax(factor(q), n);

        for _ in 0..16 {
            let inputs = (0..n).map(|_| rng.gen_u128() % (q / 2)).collect::<Vec<_>>();
            let expected = *inputs.iter().max().unwrap();

            let inputs = inputs
                .into_iter()
                .map(|x| DummyVal::to_crt(x, q))
                .collect::<Vec<_>>();
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = DummyVal::from_crt(&z, q);
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

            let x = rng.gen_u128() % q;
            let expected = to_pmr_pt(x, &ps);
            let c = circuits::crt_proj_gadgets::TestCrtToPmr(ps);

            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &x_input).unwrap();
            let output = z.wires().iter().map(|w| w.val()).collect::<Vec<_>>();
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
            let c = circuits::crt_proj_gadgets::TestPmrLessThan(qs);

            let pt_x_input = DummyVal::to_crt(pt_x, q);
            let pt_y_input = DummyVal::to_crt(pt_y, q);
            let output = Dummy::eval(&c, &(pt_x_input, pt_y_input)).unwrap();
            if pt_x < pt_y {
                assert_eq!(output.val(), 1);
            } else {
                assert_eq!(output.val(), 0);
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
            let c = circuits::crt_proj_gadgets::TestPmrGreaterThanOrEqual(qs);

            let pt_x_input = DummyVal::to_crt(pt_x, q);
            let pt_y_input = DummyVal::to_crt(pt_y, q);
            let output = Dummy::eval(&c, &(pt_x_input, pt_y_input)).unwrap();
            if pt_x >= pt_y {
                assert_eq!(output.val(), 1);
            } else {
                assert_eq!(output.val(), 0);
            }
        }
    }
}

#[cfg(test)]
mod arithmetic_proj_bundle_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::{RngExt, as_mixed_radix, factor, product},
    };

    #[test]
    fn test_eq_bundles() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::arithmetic_proj_bundle_gadgets::TestEqBundles(factor(q));

        // Let's have at least one test where they are surely equal.
        let x = rng.gen_u128() % q;
        let x_input = DummyVal::to_crt(x, q);
        let output = Dummy::eval(&c, &(x_input.clone(), x_input)).unwrap();
        assert_eq!(output.val(), (x == x) as u16);

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_crt(x, q);
            let y_input = DummyVal::to_crt(y, q);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(output.val(), (x == y) as u16);
        }
    }

    #[test]
    fn test_mixed_radix_addition() {
        let mut rng = thread_rng();
        let nargs = 2 + rng.gen_usize() % 100;
        let moduli = (0..7).map(|_| rng.gen_modulus()).collect::<Vec<_>>();
        let q: u128 = moduli.iter().map(|&q| q as u128).product();
        let circ =
            circuits::arithmetic_proj_bundle_gadgets::TestMixedRadixAddition(moduli.clone(), nargs);

        // Test maximum overflow.
        let inputs = (0..nargs)
            .map(|_| DummyVal::to_mixed_radix(q - 1, &moduli))
            .collect::<Vec<_>>();
        let output = Dummy::eval(&circ, &inputs).unwrap();
        assert_eq!(
            DummyVal::from_mixed_radix(&output),
            (q - 1) * (nargs as u128) % q
        );

        // Test random values.
        for _ in 0..4 {
            let mut expected = 0;
            let mut inputs = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % q;
                expected = (expected + x) % q;
                inputs.push(DummyVal::to_mixed_radix(x, &moduli));
            }
            let output = Dummy::eval(&circ, &inputs).unwrap();
            assert_eq!(DummyVal::from_mixed_radix(&output), expected);
        }
    }

    #[test]
    fn test_mixed_radix_addition_msb_only() {
        let mut rng = thread_rng();
        let nargs = 2 + rng.gen_usize() % 10;
        let moduli = (0..7).map(|_| rng.gen_modulus()).collect::<Vec<_>>();
        let q = product(&moduli);
        let circ = circuits::arithmetic_proj_bundle_gadgets::TestMixedRadixAdditionMSBOnly(
            moduli.clone(),
            nargs,
        );

        // Test maximum overflow.
        let inputs = (0..nargs)
            .map(|_| DummyVal::to_mixed_radix(q - 1, &moduli))
            .collect::<Vec<_>>();
        let output = Dummy::eval(&circ, &inputs).unwrap();
        assert_eq!(
            output.val(),
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
                inputs.push(DummyVal::to_mixed_radix(x, &moduli));
            }
            let output = Dummy::eval(&circ, &inputs).unwrap();
            assert_eq!(
                output.val(),
                *as_mixed_radix(expected, &moduli).last().unwrap()
            );
        }
    }
}

#[cfg(test)]
mod binary_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };

    #[test]
    fn test_binary_subtraction() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinarySubtraction(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let outputs = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(
                DummyVal::from_binary(&outputs.1),
                x.overflowing_sub(y).0 % q
            );
            assert_eq!(outputs.0.val(), (y != 0 && x >= y) as u16);
        }
    }

    #[test]
    fn test_binary_lt() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinaryLessThan(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(output.val() > 0, x < y);
        }
    }

    #[test]
    fn test_binary_lt_signed() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinaryLessThanSigned(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(output.val() > 0, (x as i16) < (y as i16));
        }
    }

    #[test]
    fn test_binary_multiplication_lower_half() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinaryMultiplicationLowerHalf(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), (x * y) % q);
        }
    }

    #[test]
    fn test_binary_multiplication() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << 64;
        let c = circuits::binary_gadgets::TestBinaryMultiplication(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x * y);
        }
    }

    #[test]
    fn test_binary_division() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinaryDivision(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let mut y = rng.gen_u128() % q;
            while y == 0 {
                y = rng.gen_u128() % q;
            }
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x / y);
        }
    }

    #[test]
    fn test_bin_abs() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinaryAbs(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let output = Dummy::eval(&c, &DummyVal::to_binary(x, nbits)).unwrap();
            assert_eq!(
                DummyVal::from_binary(&output),
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
        let c = circuits::binary_gadgets::TestBinaryEqBundles(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let y_input = DummyVal::to_binary(y, nbits);
            let output = Dummy::eval(&c, &(x_input, y_input)).unwrap();
            assert_eq!(output.val(), (x == y) as u16);
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
            let c = circuits::binary_gadgets::TestBinaryArithmeticRightShift(nbits, shift_size);
            let output = Dummy::eval(&c, &DummyVal::to_binary(x, nbits)).unwrap();
            assert_eq!(
                DummyVal::from_binary(&output) as i64,
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
            let c = circuits::binary_gadgets::TestBinaryLogicalRightShift(nbits, shift_size);
            let output = Dummy::eval(&c, &DummyVal::to_binary(x, nbits)).unwrap();
            assert_eq!(DummyVal::from_binary(&output), x >> shift_size);
        }
    }

    #[test]
    fn test_bin_demux() {
        let mut rng = thread_rng();
        let nbits = 8;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinaryDemux(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let output = Dummy::eval(&c, &x_input).unwrap();
            for (i, y) in output.into_iter().enumerate() {
                if i as u128 == x {
                    assert_eq!(y.val(), 1);
                } else {
                    assert_eq!(y.val(), 0);
                }
            }
        }
    }

    #[test]
    fn test_bin_twos_complement() {
        let mut rng = thread_rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinaryTwosComplement(nbits);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let x_input = DummyVal::to_binary(x, nbits);
            let output = Dummy::eval(&c, &x_input).unwrap();
            assert_eq!(DummyVal::from_binary(&output), (((!x) % q) + 1) % q);
        }
    }

    #[test]
    fn test_binary_max() {
        let mut rng = thread_rng();
        let n = 10;
        let nbits = 16;
        let q = 1 << nbits;
        let c = circuits::binary_gadgets::TestBinaryMax(nbits, n);

        for _ in 0..16 {
            let inputs = (0..n).map(|_| rng.gen_u128() % q).collect::<Vec<_>>();
            let expected = *inputs.iter().max().unwrap();

            let inputs = inputs
                .into_iter()
                .map(|x| DummyVal::to_binary(x, nbits))
                .collect::<Vec<_>>();
            let z = Dummy::eval(&c, &inputs).unwrap();
            let output = DummyVal::from_binary(&z);
            assert_eq!(output, expected);
        }
    }
}
